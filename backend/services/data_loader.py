"""
CyberVision AI – Data Loader Service
Handles CSV loading, column detection and sample data generation.
"""

from __future__ import annotations

import io
import logging
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd

logger = logging.getLogger("cybervision.data_loader")

# ---------------------------------------------------------------------------
# Standard column aliases: canonical name → list of possible raw column names
# ---------------------------------------------------------------------------
_COLUMN_ALIASES: dict[str, list[str]] = {
    "label": ["label", "category", "attack_type", "class", "type", "attack", "target", "classification"],
    "timestamp": ["timestamp", "time", "datetime", "date", "ts", "flow_start_time", "start_time"],
    "protocol": ["protocol", "proto", "protocol_type", "network_protocol"],
    "src_ip": ["src_ip", "source_ip", "srcip", "src", "source", "ip_src", "src_addr"],
    "dst_ip": ["dst_ip", "destination_ip", "dstip", "dst", "destination", "ip_dst", "dst_addr"],
    "severity": ["severity", "threat_level", "risk", "priority", "level"],
    "duration": ["duration", "flow_duration", "length", "elapsed"],
    "bytes": ["bytes", "total_bytes", "flow_bytes", "byte_count", "total_length", "fwd_bwd_bytes"],
}


def load_csv(file_path: str) -> pd.DataFrame:
    """
    Load a CSV file from disk, trying multiple encodings.

    Parameters
    ----------
    file_path:
        Absolute or relative path to the CSV file.

    Returns
    -------
    pd.DataFrame
        Loaded dataframe.

    Raises
    ------
    FileNotFoundError
        If the file does not exist.
    ValueError
        If the file cannot be parsed as CSV.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"CSV file not found: {file_path}")

    encodings = ("utf-8", "latin-1", "cp1252", "utf-16")
    last_error: Optional[Exception] = None

    for enc in encodings:
        try:
            df = pd.read_csv(path, encoding=enc, low_memory=False)
            logger.info("Loaded %s with encoding=%s, shape=%s", path.name, enc, df.shape)
            return df
        except (UnicodeDecodeError, pd.errors.ParserError) as exc:
            last_error = exc
            continue

    raise ValueError(f"Could not parse '{file_path}': {last_error}")


def detect_columns(df: pd.DataFrame) -> dict[str, str | None]:
    """
    Detect which standard columns exist in *df* by fuzzy name matching.

    Parameters
    ----------
    df:
        Raw dataframe whose columns should be inspected.

    Returns
    -------
    dict
        Mapping of canonical name → actual column name in *df* (or ``None``
        if the column was not found).

    Example
    -------
    >>> detect_columns(df)
    {"label": "Label", "timestamp": "Timestamp", "protocol": None, ...}
    """
    raw_cols_lower = {c.strip().lower(): c for c in df.columns}
    col_map: dict[str, str | None] = {}

    for canonical, aliases in _COLUMN_ALIASES.items():
        found: str | None = None
        for alias in aliases:
            if alias in raw_cols_lower:
                found = raw_cols_lower[alias]
                break
        col_map[canonical] = found

    logger.debug("Detected column map: %s", col_map)
    return col_map


def validate_dataframe(df: pd.DataFrame) -> tuple[bool, str]:
    """
    Perform basic sanity checks on a loaded dataframe.

    Parameters
    ----------
    df:
        Dataframe to validate.

    Returns
    -------
    tuple[bool, str]
        ``(True, "")`` if valid, ``(False, reason)`` otherwise.
    """
    if df is None:
        return False, "Dataframe is None"
    if df.empty:
        return False, "Dataframe is empty"
    if len(df.columns) < 2:
        return False, f"Too few columns ({len(df.columns)}); expected at least 2"
    if len(df) < 1:
        return False, "No rows found in the file"
    return True, ""


def get_sample_data() -> pd.DataFrame:
    """
    Return a built-in, realistic sample dataset for demonstration purposes.

    The sample dataset mirrors the schema of CICIDS-style network flow data
    and is loaded from ``data/sample_dataset.csv`` if it exists; otherwise
    a small in-memory fallback is generated.

    Returns
    -------
    pd.DataFrame
        Sample dataset with at least 100 rows.
    """
    # Try the bundled sample CSV first
    candidates = [
        Path(__file__).resolve().parent.parent / "data" / "sample_dataset.csv",
        Path("data") / "sample_dataset.csv",
    ]
    for p in candidates:
        if p.exists():
            try:
                df = load_csv(str(p))
                logger.info("Loaded bundled sample dataset from %s", p)
                return df
            except Exception as exc:
                logger.warning("Could not load sample from %s: %s", p, exc)

    # Fallback: generate a minimal in-memory sample
    logger.info("Generating in-memory fallback sample dataset")
    return _generate_fallback_sample()


def _generate_fallback_sample(n: int = 200) -> pd.DataFrame:
    """Generate a minimal in-memory sample dataset."""
    rng = np.random.default_rng(42)
    labels = ["BENIGN"] * int(n * 0.6) + ["DoS Hulk", "DDoS", "PortScan", "Brute Force"] * (n // 20 + 1)
    labels = labels[:n]
    rng.shuffle(labels)

    protocols = rng.choice(["TCP", "UDP", "ICMP"], size=n, p=[0.6, 0.3, 0.1])
    severity_map = {
        "BENIGN": "Low",
        "DoS Hulk": "High",
        "DDoS": "Critical",
        "PortScan": "Medium",
        "Brute Force": "High",
    }

    base_ts = pd.Timestamp("2023-01-01")
    timestamps = [base_ts + pd.Timedelta(seconds=int(rng.integers(0, 7 * 86400))) for _ in range(n)]

    def _ip(rng: np.random.Generator) -> str:
        return ".".join(str(rng.integers(1, 255)) for _ in range(4))

    df = pd.DataFrame({
        "timestamp": [t.strftime("%Y-%m-%d %H:%M:%S") for t in timestamps],
        "label": labels,
        "protocol": protocols,
        "src_ip": [_ip(rng) for _ in range(n)],
        "dst_ip": [_ip(rng) for _ in range(n)],
        "src_port": rng.integers(1024, 65535, size=n),
        "dst_port": rng.choice([80, 443, 22, 21, 3389, 8080], size=n),
        "duration": rng.exponential(scale=500, size=n).round(2),
        "total_bytes": rng.integers(100, 100000, size=n),
        "severity": [severity_map.get(l, "Low") for l in labels],
    })
    return df
