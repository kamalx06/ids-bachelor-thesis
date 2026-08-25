"""
Hybrid RF + IsolationForest inference for the AI IDS.

Models are loaded once at import time and can be hot-reloaded from disk after
a successful retrain (see reload_models()) without restarting the process.
Reload swaps a single immutable "bundle" reference so concurrent worker
threads calling predict() never observe a mix of old and new models (e.g. a
new RF paired with a stale scaler).
"""

from __future__ import annotations

import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn import config_context

from ai.cic_features import FEATURE_COUNT, clean_feature_matrix
from logging_config import get_logger

logger = get_logger(__name__)

_MIN_ANOMALY_STRENGTH = 0.55

# Resolve model paths relative to this file, not the process CWD. The
# retrainer (ai/retrainer.py) always saves to <repo>/ai/models regardless of
# where it's invoked from; loading must be equally CWD-independent so the
# live classifier and the retrainer always agree on which files they mean.
_MODEL_DIR = Path(__file__).resolve().parent / "models"
_TRAIN_SCRIPT = Path(__file__).resolve().parent / "train_ids_models.py"


def _run_training() -> None:
    logger.warning("Model files missing. Running train_ids_models.py")
    try:
        subprocess.run(
            [sys.executable, str(_TRAIN_SCRIPT)],
            check=True,
        )
        logger.info("Training completed successfully.")
    except subprocess.CalledProcessError as e:
        raise RuntimeError("Failed to train IDS models automatically.") from e


def _pin_single_threaded(model: Any) -> Any:
    """
    Trained models keep whatever n_jobs the retrainer used (-1, for
    CPU-bound tree building over many rows). Live inference scores one
    packet's single feature row per call, so fanning that out across
    joblib's process pool adds pickling/IPC overhead with no speedup, and
    on some platforms re-triggers a noisy (harmless) sklearn UserWarning in
    each worker process. Pinning to n_jobs=1 after loading doesn't change
    predictions at all, only how the (now-trivial) work is scheduled.
    """
    if hasattr(model, "set_params"):
        try:
            model.set_params(n_jobs=1)
        except Exception:
            pass
    return model


def _load_model(path: Path, *, required: bool = True) -> Any:
    if required and not path.exists():
        _run_training()

    try:
        with config_context(assume_finite=True):
            return _pin_single_threaded(joblib.load(path))
    except Exception as e:
        if required:
            raise RuntimeError(f"Failed to load required model: {path}") from e
        logger.warning("Optional model %s could not be loaded: %s", path, e)
        return None


@dataclass(frozen=True)
class _ModelBundle:
    rf: Any
    iso: Any | None
    scaler: Any
    expected_features: int
    rf_trusted: bool


def _build_bundle() -> _ModelBundle:
    rf = _load_model(_MODEL_DIR / "rf_model.pkl", required=True)
    iso = _load_model(_MODEL_DIR / "iso_model.pkl", required=False)
    scaler = _load_model(_MODEL_DIR / "scaler.pkl", required=True)
    feature_names = _load_model(_MODEL_DIR / "feature_names.pkl", required=False)

    expected_features = len(feature_names) if feature_names is not None else FEATURE_COUNT

    rf_classes = np.asarray(rf.classes_)
    rf_single_class = len(rf_classes) == 1
    rf_trusted = not rf_single_class

    if rf_single_class:
        logger.warning(
            "RF model trained on single class (%s). Retrain with BENIGN + attack rows.",
            rf_classes[0],
        )
    if iso is None:
        logger.warning("IsolationForest not loaded; anomaly detection disabled.")

    return _ModelBundle(
        rf=rf,
        iso=iso,
        scaler=scaler,
        expected_features=expected_features,
        rf_trusted=rf_trusted,
    )


_bundle = _build_bundle()
_reload_lock = threading.Lock()


def reload_models() -> bool:
    """
    Re-read rf/iso/scaler/feature_names from disk (e.g. right after
    ai.retrainer.retrain() writes fresh ones) and publish them atomically.

    predict() takes a single local reference to the current bundle at the
    top of each call, so an in-flight prediction on another thread sees
    either the fully-old or the fully-new set of models -- never a scaler
    from one paired with an rf from the other. Safe to call from a
    background thread while the sensor keeps classifying live traffic.

    Returns True on success; False (keeping the previous models) if the new
    files on disk are missing/corrupt.
    """
    global _bundle
    with _reload_lock:
        try:
            new_bundle = _build_bundle()
        except Exception:
            logger.error("Model reload failed; keeping previously loaded models", exc_info=True)
            return False
        _bundle = new_bundle
    logger.info(
        "AI models reloaded from disk (rf_trusted=%s, anomaly_detection=%s)",
        new_bundle.rf_trusted,
        new_bundle.iso is not None,
    )
    return True


def model_is_trusted() -> bool:
    bundle = _bundle
    return bundle.rf_trusted and bundle.iso is not None


def _attack_probability(model, X) -> float:
    with config_context(assume_finite=True):
        proba = model.predict_proba(X)[0]
    classes = np.asarray(model.classes_)

    if len(classes) == 1:
        return float(proba[0]) if classes[0] == 1 else 0.0

    attack_idx = np.where(classes == 1)[0]
    if len(attack_idx):
        return float(proba[attack_idx[0]])

    return float(np.max(proba))


def _predict_components(
    bundle: _ModelBundle, scaled: np.ndarray
) -> tuple[int, float, int, float, float]:
    """Run RF + ISO inference (read-only models; safe across worker threads)."""
    with config_context(assume_finite=True):
        rf_pred = int(bundle.rf.predict(scaled)[0])
        rf_prob = _attack_probability(bundle.rf, scaled) if bundle.rf_trusted else 0.0

        if bundle.iso is None:
            return rf_pred, rf_prob, 1, 0.0, 0.0

        iso_pred = int(bundle.iso.predict(scaled)[0])
        raw = float(bundle.iso.decision_function(scaled)[0])
    iso_score = 1.0 / (1.0 + np.exp(-raw))
    anomaly_strength = (1.0 - iso_score) if iso_pred == -1 else 0.0
    return rf_pred, rf_prob, iso_pred, iso_score, anomaly_strength


def predict(features):
    """
    Hybrid RF + IsolationForest inference.
    Returns: rf_pred, iso_pred, score, label, ai_reasons, detail_dict
    """
    bundle = _bundle  # one snapshot for the whole call, see reload_models()

    arr = clean_feature_matrix(features)
    if arr.shape[1] != bundle.expected_features:
        raise ValueError(
            f"Expected {bundle.expected_features} features, got {arr.shape[1]}. "
            "Retrain with ai/train_ids_models.py."
        )

    with config_context(assume_finite=True):
        scaled = bundle.scaler.transform(arr)
    rf_pred, rf_prob, iso_pred, iso_score, anomaly_strength = _predict_components(bundle, scaled)

    if bundle.iso is None:
        weight_rf, weight_iso = 1.0, 0.0
    elif rf_prob > 0.80:
        weight_rf, weight_iso = 0.78, 0.22
    elif rf_prob < 0.20:
        weight_rf, weight_iso = 0.30, 0.70
    elif rf_prob < 0.45:
        weight_rf, weight_iso = 0.42, 0.58
    else:
        weight_rf, weight_iso = 0.58, 0.42

    base_score = (weight_rf * rf_prob) + (weight_iso * anomaly_strength)
    # Benign RF + high ISO is common on lab traffic; cap ISO only when RF is clearly benign
    if rf_prob < 0.22 and anomaly_strength > 0.48:
        base_score = (weight_rf * rf_prob) + (weight_iso * min(anomaly_strength, 0.40))
    score = max(0.0, min(1.0, base_score))

    confidence = max(rf_prob, 1.0 - anomaly_strength) if bundle.rf_trusted else (1.0 - anomaly_strength)

    ai_reasons = []
    if rf_prob > 0.65:
        ai_reasons.append("high_rf_attack_probability")
    if anomaly_strength >= _MIN_ANOMALY_STRENGTH:
        ai_reasons.append("strong_anomaly_detected")
    if rf_prob > 0.4 and anomaly_strength > 0.3:
        ai_reasons.append("combined_ml_signals")

    if score > 0.72 or (rf_prob > 0.80 and anomaly_strength >= 0.38):
        label = "dangerous"
    elif score > 0.48 or (rf_prob > 0.55 and anomaly_strength >= 0.30):
        label = "suspicious"
    else:
        label = "safe"

    detail = {
        "rf_prob": round(rf_prob, 4),
        "iso_score": round(iso_score, 4),
        "anomaly_strength": round(anomaly_strength, 4),
        "confidence": round(confidence, 4),
        "weights": {"rf": weight_rf, "iso": weight_iso},
    }

    return rf_pred, iso_pred, score, label, ai_reasons, detail
