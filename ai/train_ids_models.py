import os
import logging
import warnings

import numpy as np

warnings.filterwarnings(
    "ignore",
    message=r"`sklearn.utils.parallel.delayed` should be used with",
    category=UserWarning,
    module=r"sklearn\.utils\.parallel",
)
import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score

from cic_features import (
    FEATURE_COUNT,
    FEATURE_NAMES,
    MIN_ISOLATION_FOREST_SAMPLES,
    clean_feature_matrix,
    features_from_dataframe,
)

from pathlib import Path

_ROOT = Path(__file__).resolve().parent
DATA_PATH = str(_ROOT / "data" / "cic_ids.csv")
MODEL_DIR = str(_ROOT / "models")
RANDOM_STATE = 42

os.makedirs(MODEL_DIR, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

logging.info("Loading dataset...")
df = pd.read_csv(DATA_PATH)
df.columns = df.columns.str.strip()

if "Label" not in df.columns:
    raise ValueError("Dataset must contain 'Label' column")

df["Label"] = df["Label"].apply(lambda x: 0 if x == "BENIGN" else 1)

logging.info("Extracting CIC-aligned features...")
features = features_from_dataframe(df)
X = clean_feature_matrix(features.values)
y = df["Label"].values

if X.shape[1] != FEATURE_COUNT:
    raise ValueError(f"Expected {FEATURE_COUNT} features, got {X.shape[1]}")

logging.info("Dataset size: %s, features: %s", X.shape, FEATURE_NAMES)

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

split_kwargs = dict(test_size=0.2, random_state=RANDOM_STATE)
if len(np.unique(y)) > 1:
    split_kwargs["stratify"] = y

X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, **split_kwargs)

logging.info("Training RandomForest...")

rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=15,
    class_weight="balanced",
    random_state=RANDOM_STATE,
    n_jobs=-1,
)

rf.fit(X_train, y_train)

y_pred = rf.predict(X_test)

logging.info("=== Random Forest Evaluation ===")
if len(np.unique(y)) > 1:
    print(classification_report(y_test, y_pred))
    proba = rf.predict_proba(X_test)
    y_prob = proba[:, 1] if proba.shape[1] > 1 else proba[:, 0]
    try:
        auc = roc_auc_score(y_test, y_prob)
        logging.info("ROC-AUC: %.4f", auc)
    except Exception:
        logging.warning("ROC-AUC could not be computed")
else:
    logging.warning(
        "Only one class in dataset (all %s). Add attack-labeled rows for meaningful metrics.",
        "BENIGN" if y[0] == 0 else "attack",
    )

logging.info("Training IsolationForest...")

normal_data = X_scaled[y == 0]
iso = None

if len(normal_data) < MIN_ISOLATION_FOREST_SAMPLES:
    logging.warning(
        "Not enough normal samples for IsolationForest (have %d, need %d). "
        "Skipping anomaly model — retrain after adding more BENIGN rows.",
        len(normal_data),
        MIN_ISOLATION_FOREST_SAMPLES,
    )
else:
    iso = IsolationForest(
        contamination=0.03,
        n_estimators=200,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    iso.fit(normal_data)

logging.info("Saving models...")

joblib.dump(rf, os.path.join(MODEL_DIR, "rf_model.pkl"))
if iso is not None:
    joblib.dump(iso, os.path.join(MODEL_DIR, "iso_model.pkl"))
joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.pkl"))
joblib.dump(FEATURE_NAMES, os.path.join(MODEL_DIR, "feature_names.pkl"))

logging.info("[SUCCESS] All models trained and saved (%d features).", FEATURE_COUNT)
