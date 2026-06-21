"""
Shared CIC-IDS-aligned feature definitions for offline training and live inference.

Training reads columns from cic_ids.csv; the live sensor builds the same vector from
per-flow state in engine.flow_manager.
"""

from __future__ import annotations

import logging
from typing import Any

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# Ordered feature vector — must match between train_ids_models.py and the sensor.
FEATURE_NAMES: list[str] = [
    "destination_port",
    "flow_duration_us",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "flow_bytes_per_s",
    "flow_packets_per_s",
    "fwd_packets_per_s",
    "bwd_packets_per_s",
    "syn_flag_count",
    "ack_flag_count",
    "rst_flag_count",
    "fin_flag_count",
    "psh_flag_count",
    "packet_length_mean",
    "packet_length_std",
    "protocol",
]

FEATURE_COUNT = len(FEATURE_NAMES)

# CIC-IDS2017 CSV column names (after .str.strip() on headers).
CSV_COLUMN_MAP: dict[str, str] = {
    "destination_port": "Destination Port",
    "flow_duration_us": "Flow Duration",
    "total_fwd_packets": "Total Fwd Packets",
    "total_bwd_packets": "Total Backward Packets",
    "total_fwd_bytes": "Total Length of Fwd Packets",
    "total_bwd_bytes": "Total Length of Bwd Packets",
    "flow_bytes_per_s": "Flow Bytes/s",
    "flow_packets_per_s": "Flow Packets/s",
    "fwd_packets_per_s": "Fwd Packets/s",
    "bwd_packets_per_s": "Bwd Packets/s",
    "syn_flag_count": "SYN Flag Count",
    "ack_flag_count": "ACK Flag Count",
    "rst_flag_count": "RST Flag Count",
    "fin_flag_count": "FIN Flag Count",
    "psh_flag_count": "PSH Flag Count",
    "packet_length_mean": "Packet Length Mean",
    "packet_length_std": "Packet Length Std",
}

MIN_ISOLATION_FOREST_SAMPLES = 50


def derive_protocol(data: pd.DataFrame) -> pd.Series:
    """Map to sensor encoding: 0=other, 1=TCP, 2=UDP."""
    if "Protocol" in data.columns:
        return data["Protocol"]

    flag_cols = [CSV_COLUMN_MAP[k] for k in (
        "syn_flag_count",
        "ack_flag_count",
        "rst_flag_count",
        "fin_flag_count",
        "psh_flag_count",
    )]
    if not all(col in data.columns for col in flag_cols):
        logger.warning(
            "No 'Protocol' column and TCP flag columns missing; defaulting protocol to 1 (TCP)."
        )
        return pd.Series(1, index=data.index)

    tcp_flags = data[flag_cols].fillna(0).sum(axis=1)
    protocol = np.where(tcp_flags > 0, 1, 2)
    logger.info("Derived protocol from TCP flags (no 'Protocol' column in dataset).")
    return pd.Series(protocol, index=data.index)


def _require_columns(df: pd.DataFrame) -> None:
    missing = [
        csv_col
        for csv_col in CSV_COLUMN_MAP.values()
        if csv_col not in df.columns
    ]
    if missing:
        raise ValueError(
            "Dataset is missing required CIC columns: "
            + ", ".join(missing)
        )


def features_from_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Build the training feature matrix from a CIC-IDS CSV dataframe."""
    _require_columns(df)

    out = pd.DataFrame(index=df.index)
    for feat, csv_col in CSV_COLUMN_MAP.items():
        out[feat] = df[csv_col]

    out["protocol"] = derive_protocol(df)
    return out[FEATURE_NAMES]


def clean_feature_matrix(values: np.ndarray) -> np.ndarray:
    """Replace non-finite values and ensure 2D float array."""
    arr = np.asarray(values, dtype=float)
    if arr.ndim == 1:
        arr = arr.reshape(1, -1)
    arr = np.nan_to_num(arr, nan=0.0, posinf=0.0, neginf=0.0)
    return arr


def vector_from_flow_snapshot(snapshot: dict[str, Any]) -> np.ndarray:
    """Shape (1, FEATURE_COUNT) for classifier.predict."""
    row = [float(snapshot[name]) for name in FEATURE_NAMES]
    return clean_feature_matrix(np.array(row))


def count_tcp_flag(tcp_layer, flag_char: str) -> int:
    """Return 1 if the TCP flag is set on this packet, else 0."""
    try:
        return 1 if getattr(tcp_layer.flags, flag_char) else 0
    except Exception:
        return 0
