import subprocess
from pathlib import Path

import joblib
import numpy as np
from sklearn import config_context

from ai.cic_features import FEATURE_COUNT, clean_feature_matrix
from logging_config import get_logger

logger = get_logger(__name__)

_MIN_ANOMALY_STRENGTH = 0.55


def _run_training():
    logger.warning("Model files missing. Running train_ids_models.py")
    try:
        subprocess.run(
            ["python", "ai/train_ids_models.py"],
            check=True,
        )
        logger.info("Training completed successfully.")
    except subprocess.CalledProcessError as e:
        raise RuntimeError("Failed to train IDS models automatically.") from e


def _load_model(path: str, *, required: bool = True):
    model_path = Path(path)
    if required and not model_path.exists():
        _run_training()

    try:
        with config_context(assume_finite=True):
            return joblib.load(path)
    except Exception as e:
        if required:
            raise RuntimeError(f"Failed to load required model: {path}") from e
        logger.warning("Optional model %s could not be loaded: %s", path, e)
        return None


rf = _load_model("ai/models/rf_model.pkl", required=True)
iso = _load_model("ai/models/iso_model.pkl", required=False)
scaler = _load_model("ai/models/scaler.pkl", required=True)
feature_names = _load_model("ai/models/feature_names.pkl", required=False)

_expected_features = (
    len(feature_names) if feature_names is not None else FEATURE_COUNT
)

_rf_classes = np.asarray(rf.classes_)
_rf_single_class = len(_rf_classes) == 1
_rf_trusted = not _rf_single_class


def model_is_trusted() -> bool:
    return _rf_trusted and iso is not None


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


def _predict_components(scaled: np.ndarray) -> tuple[int, float, int, float, float]:
    """Run RF + ISO inference (read-only models; safe across worker threads)."""
    with config_context(assume_finite=True):
        rf_pred = int(rf.predict(scaled)[0])
        rf_prob = _attack_probability(rf, scaled) if _rf_trusted else 0.0

        if iso is None:
            return rf_pred, rf_prob, 1, 0.0, 0.0

        iso_pred = int(iso.predict(scaled)[0])
        raw = float(iso.decision_function(scaled)[0])
    iso_score = 1.0 / (1.0 + np.exp(-raw))
    anomaly_strength = (1.0 - iso_score) if iso_pred == -1 else 0.0
    return rf_pred, rf_prob, iso_pred, iso_score, anomaly_strength


if _rf_single_class:
    logger.warning(
        "RF model trained on single class (%s). Retrain with BENIGN + attack rows.",
        _rf_classes[0],
    )

if iso is None:
    logger.warning("IsolationForest not loaded; anomaly detection disabled.")


def predict(features):
    """
    Hybrid RF + IsolationForest inference.
    Returns: rf_pred, iso_pred, score, label, ai_reasons, detail_dict
    """
    arr = clean_feature_matrix(features)
    if arr.shape[1] != _expected_features:
        raise ValueError(
            f"Expected {_expected_features} features, got {arr.shape[1]}. "
            "Retrain with ai/train_ids_models.py."
        )

    with config_context(assume_finite=True):
        scaled = scaler.transform(arr)
    rf_pred, rf_prob, iso_pred, iso_score, anomaly_strength = _predict_components(scaled)

    if iso is None:
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

    confidence = max(rf_prob, 1.0 - anomaly_strength) if _rf_trusted else (1.0 - anomaly_strength)

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
