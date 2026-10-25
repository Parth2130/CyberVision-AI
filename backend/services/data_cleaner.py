"""
CyberVision AI – Data Cleaner Service
Cleans and preprocesses raw network-flow dataframes.
"""

from __future__ import annotations

import logging
from typing import Any

import numpy as np
import pandas as pd

logger = logging.getLogger("cybervision.data_cleaner")

# ---------------------------------------------------------------------------
# Severity normalisation map
# ---------------------------------------------------------------------------
_SEVERITY_NORM: dict[str, str] = {
    # Low variants
    "low": "Low", "l": "Low", "0": "Low", "info": "Low", "informational": "Low", "none": "Low",
    # Medium variants
    "medium": "Medium", "med": "Medium", "m": "Medium", "1": "Medium", "moderate": "Medium", "warning": "Medium",
    # High variants
    "high": "High", "h": "High", "2": "High",
    # Critical variants
    "critical": "Critical", "crit": "Critical", "c": "Critical", "3": "Critical",
    "very high": "Critical", "extreme": "Critical", "emergency": "Critical",
}

# ---------------------------------------------------------------------------
# Protocol normalisation map
# ---------------------------------------------------------------------------
_PROTOCOL_NORM: dict[str, str] = {
    "tcp": "TCP", "6": "TCP",
    "udp": "UDP", "17": "UDP",
    "icmp": "ICMP", "1": "ICMP",
    "icmpv6": "ICMP", "58": "ICMP",
}


def clean_dataframe(df: pd.DataFrame, column_map: dict[str, str | None]) -> pd.DataFrame:
    """
    Clean and normalise a raw network-flow dataframe.

    Steps performed:
    1. Strip whitespace from all string column names.
    2. Drop exact duplicate rows.
    3. Fill missing numeric values with column medians.
    4. Fill missing categorical values with ``'Unknown'``.
    5. Parse timestamp column to ``datetime64`` when present.
    6. Normalise severity labels (Low / Medium / High / Critical).
    7. Normalise protocol names (TCP / UDP / ICMP / Other).

    Parameters
    ----------
    df:
        Raw dataframe as loaded from CSV.
    column_map:
        Canonical → actual column name mapping (from :func:`detect_columns`).

    Returns
    -------
    pd.DataFrame
        Cleaned copy of the input dataframe.
    """
    try:
        df = df.copy()

        # ── 1. Normalise column names ──────────────────────────────────────
        df.columns = [str(c).strip() for c in df.columns]

        # ── 2. Drop duplicate rows ─────────────────────────────────────────
        before_dedup = len(df)
        df = df.drop_duplicates()
        logger.debug("Dropped %d duplicate rows", before_dedup - len(df))

        # ── 3 & 4. Handle missing values ───────────────────────────────────
        for col in df.columns:
            if df[col].dtype in (np.float64, np.int64, float, int):
                median_val = df[col].median()
                df[col] = df[col].fillna(median_val if not np.isnan(median_val) else 0)
            else:
                df[col] = df[col].fillna("Unknown")

        # ── 5. Parse timestamp ─────────────────────────────────────────────
        ts_col = column_map.get("timestamp")
        if ts_col and ts_col in df.columns:
            df[ts_col] = pd.to_datetime(df[ts_col], errors="coerce")
            invalid_ts = df[ts_col].isna().sum()
            if invalid_ts:
                logger.debug("%d rows have unparseable timestamps (set to NaT)", invalid_ts)

        # ── 6. Normalise severity ──────────────────────────────────────────
        sev_col = column_map.get("severity")
        if sev_col and sev_col in df.columns:
            df[sev_col] = df[sev_col].apply(_normalise_severity)

        # ── 7. Normalise protocol ──────────────────────────────────────────
        proto_col = column_map.get("protocol")
        if proto_col and proto_col in df.columns:
            df[proto_col] = df[proto_col].apply(_normalise_protocol)

        logger.info("Cleaning complete. Final shape: %s", df.shape)
        return df

    except Exception as exc:
        logger.exception("clean_dataframe failed: %s", exc)
        raise


def get_cleaning_report(original_df: pd.DataFrame, cleaned_df: pd.DataFrame) -> dict[str, Any]:
    """
    Produce a summary comparing the original and cleaned dataframes.

    Parameters
    ----------
    original_df:
        Dataframe before cleaning.
    cleaned_df:
        Dataframe after cleaning.

    Returns
    -------
    dict
        Keys:

        - ``original_rows``
        - ``cleaned_rows``
        - ``duplicates_removed``
        - ``nulls_filled``
        - ``columns_processed``
    """
    original_rows = len(original_df)
    cleaned_rows = len(cleaned_df)
    duplicates_removed = original_rows - cleaned_rows
    nulls_filled = int(original_df.isna().sum().sum())

    return {
        "original_rows": original_rows,
        "cleaned_rows": cleaned_rows,
        "duplicates_removed": max(duplicates_removed, 0),
        "nulls_filled": nulls_filled,
        "columns_processed": len(original_df.columns),
    }


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _normalise_severity(value: Any) -> str:
    """Map a raw severity string to Low / Medium / High / Critical."""
    if pd.isna(value):
        return "Low"
    key = str(value).strip().lower()
    return _SEVERITY_NORM.get(key, "Low")


def _normalise_protocol(value: Any) -> str:
    """Map a raw protocol string to TCP / UDP / ICMP / Other."""
    if pd.isna(value):
        return "Other"
    key = str(value).strip().lower()
    return _PROTOCOL_NORM.get(key, "Other" if key not in ("tcp", "udp", "icmp") else key.upper())
