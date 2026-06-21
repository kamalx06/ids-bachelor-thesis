"""
Unified model retraining for the AI IDS.

Training reads exclusively from the training_data table (MySQL primary, SQLite fallback).
Live IDS traffic is collected into that table by ids_engine.py.

Incremental mode (default): extends the existing RandomForest with new trees trained on
all rows in training_data, then refits scaler/ISO on the combined dataset.

Bootstrap empty table from CIC CSV:
  python -m ai.retrainer --seed-csv ai/data/cic_ids.csv --seed-max-rows 5000 --train

CLI:
  python -m ai.retrainer --preview
  python -m ai.retrainer --source mysql
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import tempfile
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sqlalchemy import text

from ai.cic_features import (
    FEATURE_COUNT,
    FEATURE_NAMES,
    MIN_ISOLATION_FOREST_SAMPLES,
    clean_feature_matrix,
    features_from_dataframe,
)
from logging_config import get_logger

logger = get_logger(__name__)

_ROOT = Path(__file__).resolve().parent
DEFAULT_MODEL_DIR = _ROOT / "models"
DEFAULT_CSV = _ROOT / "data" / "cic_ids.csv"

SourceName = Literal["auto", "sqlite", "mysql", "csv"]

warnings.filterwarnings(
    "ignore",
    message=r"`sklearn.utils.parallel.delayed` should be used with",
    category=UserWarning,
    module=r"sklearn\.utils\.parallel",
)


@dataclass
class RetrainConfig:
    model_dir: Path = field(default_factory=lambda: DEFAULT_MODEL_DIR)
    min_samples: int = 100
    test_size: float = 0.2
    random_state: int = 42
    rf_n_estimators: int = 300
    iso_contamination: float = 0.02
    sqlite_path: str | None = None
    use_mysql: bool = True
    csv_path: Path | None = None
    source: SourceName = "auto"
    allow_csv_fallback: bool = False
    incremental: bool = True
    incremental_trees: int = 100


@dataclass
class RetrainResult:
    sample_count: int
    train_count: int
    test_count: int
    metrics: dict[str, Any]
    saved_iso: bool
    model_dir: Path
    source: str
    incremental: bool = False


def _label_to_binary(label: Any) -> int:
    if isinstance(label, (int, float, np.integer, np.floating)):
        return int(label)
    text_label = str(label).strip().lower()
    if text_label in {"0", "safe", "benign", "normal"}:
        return 0
    return 1


def _parse_feature_vector(raw: Any) -> np.ndarray | None:
    if raw is None:
        return None
    try:
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8", errors="replace")
        if isinstance(raw, str):
            data = json.loads(raw)
        else:
            data = raw
        arr = np.asarray(data, dtype=float).ravel()
        if not np.isfinite(arr).all():
            arr = np.nan_to_num(arr, nan=0.0, posinf=0.0, neginf=0.0)
        if arr.size == 0:
            return None
        return arr
    except (json.JSONDecodeError, TypeError, ValueError):
        return None


def _merge_samples(
    X_parts: list[np.ndarray],
    y_parts: list[np.ndarray],
) -> tuple[np.ndarray, np.ndarray]:
    if not X_parts:
        return np.empty((0, FEATURE_COUNT)), np.array([], dtype=int)
    X = clean_feature_matrix(np.vstack(X_parts))
    y = np.concatenate(y_parts).astype(int)
    return X, y


def _load_from_sqlite(db_path: str) -> tuple[np.ndarray, np.ndarray, int]:
    from storage.persistent_store import ensure_sqlite_schema

    ensure_sqlite_schema()
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    skipped = 0
    X_list: list[np.ndarray] = []
    y_list: list[int] = []

    cur = conn.cursor()
    try:
        cur.execute("SELECT features_json, label FROM training_data")
    except sqlite3.OperationalError:
        cur.execute("SELECT features AS features_json, label FROM training_data")

    for row in cur.fetchall():
        feat_col = row["features_json"] if "features_json" in row.keys() else row[0]
        label_col = row["label"] if "label" in row.keys() else row[1]
        vec = _parse_feature_vector(feat_col)
        if vec is None:
            skipped += 1
            continue
        X_list.append(vec)
        y_list.append(_label_to_binary(label_col))

    conn.close()
    if not X_list:
        return np.empty((0, FEATURE_COUNT)), np.array([], dtype=int), skipped

    return clean_feature_matrix(np.vstack(X_list)), np.asarray(y_list, dtype=int), skipped


def _load_from_mysql() -> tuple[np.ndarray, np.ndarray, int]:
    from storage.db import get_session

    session = get_session()
    skipped = 0
    X_list: list[np.ndarray] = []
    y_list: list[int] = []

    try:
        try:
            rows = session.execute(
                text("SELECT features_json, label FROM training_data")
            ).all()
        except Exception:
            rows = session.execute(text("SELECT features, label FROM training_data")).all()

        for feat_raw, label in rows:
            vec = _parse_feature_vector(feat_raw)
            if vec is None:
                skipped += 1
                continue
            X_list.append(vec)
            y_list.append(_label_to_binary(label))
    finally:
        session.close()

    if not X_list:
        return np.empty((0, FEATURE_COUNT)), np.array([], dtype=int), skipped

    return clean_feature_matrix(np.vstack(X_list)), np.asarray(y_list, dtype=int), skipped


def _load_from_csv(csv_path: Path) -> tuple[np.ndarray, np.ndarray, int]:
    import pandas as pd

    if not csv_path.is_file():
        raise FileNotFoundError(f"CSV not found: {csv_path}")

    df = pd.read_csv(csv_path)
    df.columns = df.columns.str.strip()
    if "Label" not in df.columns:
        raise ValueError("CSV must contain a Label column")

    df["Label"] = df["Label"].apply(
        lambda x: 0 if str(x).strip().upper() == "BENIGN" else 1
    )
    features = features_from_dataframe(df)
    X = clean_feature_matrix(features.values)
    y = df["Label"].values.astype(int)
    return X, y, 0


def load_training_dataset(config: RetrainConfig) -> tuple[np.ndarray, np.ndarray, int, str]:
    """Return X, y, skipped_rows, source_label."""
    if config.source == "csv":
        if not config.csv_path:
            raise ValueError("--csv path required when --source csv")
        X, y, skipped = _load_from_csv(config.csv_path)
        return X, y, skipped, f"csv:{config.csv_path}"

    if config.source == "sqlite":
        sqlite_path = config.sqlite_path or os.environ.get("DB_PATH", "ids.db")
        X, y, skipped = _load_from_sqlite(sqlite_path)
        return X, y, skipped, f"sqlite:{sqlite_path}"

    if config.source == "mysql":
        X, y, skipped = _load_from_mysql()
        return X, y, skipped, "mysql:training_data"

    if config.csv_path and config.csv_path.is_file():
        X, y, skipped = _load_from_csv(config.csv_path)
        return X, y, skipped, f"csv:{config.csv_path}"

    sqlite_path = config.sqlite_path or os.environ.get("DB_PATH", "ids.db")
    X_sql, y_sql, skipped_sql = _load_from_sqlite(sqlite_path)

    X_mysql = np.empty((0, FEATURE_COUNT))
    y_mysql = np.array([], dtype=int)
    skipped_mysql = 0
    if config.use_mysql:
        try:
            X_mysql, y_mysql, skipped_mysql = _load_from_mysql()
        except Exception as exc:
            logger.debug("MySQL training_data unavailable: %s", exc)

    if len(y_mysql) and len(y_sql):
        X, y = _merge_samples([X_mysql, X_sql], [y_mysql, y_sql])
        skipped = skipped_mysql + skipped_sql
        source = f"mysql+sqlite ({len(y_mysql)}+{len(y_sql)} rows)"
        return X, y, skipped, source

    if len(y_mysql):
        return X_mysql, y_mysql, skipped_mysql, "mysql:training_data"

    if len(y_sql):
        return X_sql, y_sql, skipped_sql, f"sqlite:{sqlite_path}"

    if config.allow_csv_fallback and DEFAULT_CSV.is_file():
        X, y, skipped = _load_from_csv(DEFAULT_CSV)
        return X, y, skipped, f"csv-fallback:{DEFAULT_CSV}"

    return X_sql, y_sql, skipped_sql + skipped_mysql, "none"


def _atomic_joblib_dump(obj: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), suffix=".pkl.tmp")
    os.close(fd)
    tmp_path = Path(tmp_name)
    try:
        joblib.dump(obj, tmp_path)
        tmp_path.replace(path)
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        raise


def _evaluate_classifier(
    rf: RandomForestClassifier,
    X_test: np.ndarray,
    y_test: np.ndarray,
) -> dict[str, Any]:
    y_pred = rf.predict(X_test)
    metrics: dict[str, Any] = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "f1_macro": float(f1_score(y_test, y_pred, average="macro", zero_division=0)),
    }
    if len(np.unique(y_test)) > 1:
        proba = rf.predict_proba(X_test)
        y_prob = proba[:, 1] if proba.shape[1] > 1 else proba[:, 0]
        try:
            metrics["roc_auc"] = float(roc_auc_score(y_test, y_prob))
        except Exception:
            metrics["roc_auc"] = None
        metrics["report"] = classification_report(y_test, y_pred, zero_division=0)
    return metrics


def _fit_random_forest(
    cfg: RetrainConfig,
    X_train_scaled: np.ndarray,
    y_train: np.ndarray,
) -> tuple[RandomForestClassifier, bool]:
    """Train RF from scratch or extend an existing forest (warm_start)."""
    rf_path = cfg.model_dir / "rf_model.pkl"
    if cfg.incremental and rf_path.is_file():
        try:
            existing = joblib.load(rf_path)
            if isinstance(existing, RandomForestClassifier):
                old_trees = int(existing.n_estimators)
                target_trees = old_trees + max(1, int(cfg.incremental_trees))
                existing.set_params(
                    warm_start=True,
                    n_estimators=target_trees,
                    class_weight="balanced_subsample",
                    n_jobs=-1,
                )
                existing.fit(X_train_scaled, y_train)
                logger.info(
                    "Incremental RF: kept %d trees, added %d new trees (total %d)",
                    old_trees,
                    target_trees - old_trees,
                    target_trees,
                )
                return existing, True
        except Exception as exc:
            logger.warning("Incremental RF load failed, training fresh model: %s", exc)

    rf = RandomForestClassifier(
        n_estimators=cfg.rf_n_estimators,
        max_depth=None,
        n_jobs=-1,
        class_weight="balanced_subsample",
        random_state=cfg.random_state,
    )
    rf.fit(X_train_scaled, y_train)
    return rf, False


def _fit_isolation_forest(
    cfg: RetrainConfig,
    normal_train: np.ndarray,
) -> tuple[IsolationForest | None, bool]:
    """Fit ISO on benign rows; keep existing model if data is insufficient."""
    iso_path = cfg.model_dir / "iso_model.pkl"
    if len(normal_train) >= MIN_ISOLATION_FOREST_SAMPLES:
        iso = IsolationForest(
            contamination=cfg.iso_contamination,
            n_estimators=200,
            random_state=cfg.random_state,
            n_jobs=-1,
        )
        iso.fit(normal_train)
        return iso, True

    if cfg.incremental and iso_path.is_file():
        try:
            existing = joblib.load(iso_path)
            if isinstance(existing, IsolationForest):
                logger.info(
                    "Keeping existing IsolationForest (%d benign samples < %d)",
                    len(normal_train),
                    MIN_ISOLATION_FOREST_SAMPLES,
                )
                return existing, True
        except Exception:
            pass

    logger.info(
        "Skipping IsolationForest (normal samples %d < %d)",
        len(normal_train),
        MIN_ISOLATION_FOREST_SAMPLES,
    )
    return None, False


def seed_training_table_from_csv(
    csv_path: Path,
    *,
    use_mysql: bool = True,
    sqlite_path: str | None = None,
    max_rows: int | None = None,
    batch_size: int = 500,
) -> int:
    """
    Import labeled CIC-IDS rows into training_data so retraining uses the table only.
    Returns number of rows inserted.
    """
    X, y, _ = _load_from_csv(csv_path)
    if len(y) == 0:
        return 0

    limit = len(y) if max_rows is None else min(len(y), int(max_rows))
    inserted = 0
    now = time.time()

    def _rows(start: int, end: int) -> list[dict]:
        out: list[dict] = []
        for i in range(start, end):
            label = "benign" if int(y[i]) == 0 else "attack"
            out.append(
                {
                    "created_at": now,
                    "features_json": json.dumps(X[i].ravel().tolist()),
                    "label": label,
                }
            )
        return out

    if use_mysql:
        from storage.db import get_session

        session = get_session()
        try:
            from sqlalchemy import text

            stmt = text(
                "INSERT INTO training_data (created_at, features_json, label) "
                "VALUES (:created_at, :features_json, :label)"
            )
            for start in range(0, limit, batch_size):
                batch = _rows(start, min(start + batch_size, limit))
                session.execute(stmt, batch)
                inserted += len(batch)
            session.commit()
            logger.info("Seeded %d rows into MySQL training_data from %s", inserted, csv_path)
        except Exception:
            session.rollback()
            logger.error("Failed to seed MySQL training_data from CSV", exc_info=True)
            raise
        finally:
            session.close()
    else:
        db_path = sqlite_path or os.environ.get("DB_PATH", "ids.db")
        from storage.persistent_store import ensure_sqlite_schema

        ensure_sqlite_schema()
        conn = sqlite3.connect(db_path, timeout=10)
        try:
            cur = conn.cursor()
            for start in range(0, limit, batch_size):
                batch = _rows(start, min(start + batch_size, limit))
                cur.executemany(
                    "INSERT INTO training_data (created_at, features_json, label) VALUES (?, ?, ?)",
                    [(r["created_at"], r["features_json"], r["label"]) for r in batch],
                )
                inserted += len(batch)
            conn.commit()
            logger.info("Seeded %d rows into SQLite training_data from %s", inserted, csv_path)
        finally:
            conn.close()

    return inserted


def retrain(config: RetrainConfig | None = None) -> RetrainResult | None:
    """Train and save models. Returns None when sample count is below min_samples."""
    cfg = config or RetrainConfig()
    cfg.model_dir.mkdir(parents=True, exist_ok=True)

    X, y, skipped, source = load_training_dataset(cfg)
    if len(y) < cfg.min_samples:
        logger.info(
            "Not enough training samples (have %d, need >= %d, source=%s, skipped=%d)",
            len(y),
            cfg.min_samples,
            source,
            skipped,
        )
        return None

    if X.shape[1] != FEATURE_COUNT:
        logger.error(
            "Feature dimension mismatch: data has %d, models expect %d. "
            "Clear stale training_data or recollect samples.",
            X.shape[1],
            FEATURE_COUNT,
        )
        return None

    split_kwargs: dict[str, Any] = {
        "test_size": cfg.test_size,
        "random_state": cfg.random_state,
    }
    if len(np.unique(y)) > 1:
        split_kwargs["stratify"] = y

    X_train, X_test, y_train, y_test = train_test_split(X, y, **split_kwargs)

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    rf, was_incremental = _fit_random_forest(cfg, X_train_scaled, y_train)
    metrics = _evaluate_classifier(rf, X_test_scaled, y_test)

    logger.info("=== Random Forest evaluation (source: %s) ===", source)
    logger.info(
        "mode=%s accuracy=%.4f f1_macro=%.4f",
        "incremental" if was_incremental else "full",
        metrics["accuracy"],
        metrics["f1_macro"],
    )
    if metrics.get("roc_auc") is not None:
        logger.info("roc_auc=%.4f", metrics["roc_auc"])
    if metrics.get("report"):
        logger.info("\n%s", metrics["report"])

    normal_train = X_train_scaled[y_train == 0]
    iso, saved_iso = _fit_isolation_forest(cfg, normal_train)

    feature_names_path = cfg.model_dir / "feature_names.pkl"
    try:
        feature_names = joblib.load(feature_names_path)
    except Exception:
        feature_names = FEATURE_NAMES

    _atomic_joblib_dump(rf, cfg.model_dir / "rf_model.pkl")
    if iso is not None:
        _atomic_joblib_dump(iso, cfg.model_dir / "iso_model.pkl")
    _atomic_joblib_dump(scaler, cfg.model_dir / "scaler.pkl")
    _atomic_joblib_dump(feature_names, feature_names_path)

    logger.info(
        "Models saved to %s (%d samples, ISO=%s, source=%s, incremental=%s)",
        cfg.model_dir,
        len(y),
        "yes" if saved_iso else "no",
        source,
        was_incremental,
    )

    return RetrainResult(
        sample_count=len(y),
        train_count=len(y_train),
        test_count=len(y_test),
        metrics=metrics,
        saved_iso=saved_iso,
        model_dir=cfg.model_dir,
        source=source,
        incremental=was_incremental,
    )


def preview_dataset(config: RetrainConfig | None = None) -> dict[str, Any]:
    """Inspect available training rows without fitting models."""
    cfg = config or RetrainConfig()
    X, y, skipped, source = load_training_dataset(cfg)
    classes, counts = np.unique(y, return_counts=True) if len(y) else ([], [])
    return {
        "source": source,
        "sample_count": int(len(y)),
        "feature_dim": int(X.shape[1]) if len(y) else 0,
        "skipped_rows": skipped,
        "class_counts": {str(c): int(n) for c, n in zip(classes, counts)},
        "ready": len(y) >= cfg.min_samples and (len(y) == 0 or X.shape[1] == FEATURE_COUNT),
        "min_samples": cfg.min_samples,
    }


def _build_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Retrain AI IDS models from collected samples or CIC-IDS CSV",
    )
    p.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)
    p.add_argument("--min-samples", type=int, default=100)
    p.add_argument("--sqlite", dest="sqlite_path", default=None, help="SQLite DB path (default: DB_PATH env)")
    p.add_argument(
        "--csv",
        type=Path,
        default=None,
        help=f"Offline CIC-IDS CSV (default fallback: {DEFAULT_CSV.name})",
    )
    p.add_argument(
        "--source",
        choices=("auto", "sqlite", "mysql", "csv"),
        default="auto",
        help="Training data source",
    )
    p.add_argument("--no-mysql", action="store_true", help="Do not read MySQL training_data")
    p.add_argument(
        "--csv-fallback",
        action="store_true",
        help="When auto source has no rows, use ai/data/cic_ids.csv",
    )
    p.add_argument(
        "--preview",
        action="store_true",
        help="Show sample counts and exit without training",
    )
    p.add_argument(
        "--seed-csv",
        type=Path,
        default=None,
        help="Import CIC-IDS CSV rows into training_data table (then exit unless --train)",
    )
    p.add_argument(
        "--seed-max-rows",
        type=int,
        default=None,
        help="Limit rows imported by --seed-csv",
    )
    p.add_argument(
        "--train",
        action="store_true",
        help="Run training after --seed-csv",
    )
    p.add_argument(
        "--no-incremental",
        action="store_true",
        help="Train a fresh model instead of extending the current RF",
    )
    p.add_argument(
        "--incremental-trees",
        type=int,
        default=100,
        help="Extra trees to add when extending the current RF (default: 100)",
    )
    return p


def main() -> int:
    import dotenv

    dotenv.load_dotenv()
    args = _build_cli().parse_args()
    cfg = RetrainConfig(
        model_dir=args.model_dir,
        min_samples=args.min_samples,
        sqlite_path=args.sqlite_path,
        use_mysql=not args.no_mysql,
        csv_path=args.csv,
        source=args.source,
        allow_csv_fallback=args.csv_fallback,
        incremental=not args.no_incremental,
        incremental_trees=args.incremental_trees,
    )

    if args.preview:
        info = preview_dataset(cfg)
        print(json.dumps(info, indent=2))
        return 0

    if args.seed_csv:
        inserted = seed_training_table_from_csv(
            args.seed_csv,
            use_mysql=not args.no_mysql,
            sqlite_path=args.sqlite_path,
            max_rows=args.seed_max_rows,
        )
        print(json.dumps({"seeded_rows": inserted, "csv": str(args.seed_csv)}, indent=2))
        if not args.train:
            return 0

    result = retrain(cfg)
    return 0 if result is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
