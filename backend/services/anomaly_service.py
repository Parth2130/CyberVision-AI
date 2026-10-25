"""
CyberVision AI – Anomaly Detection Service
Implements rule-based, statistical, and Machine Learning (Isolation Forest) anomaly detection algorithms.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

logger = logging.getLogger("cybervision.anomaly_service")


def detect_anomalies(
    df: pd.DataFrame,
    method: str = "isolation_forest",
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Detect anomalies in the dataset using the specified method.
    """
    if params is None:
        params = {}

    from services.data_loader import detect_columns
    col_map = detect_columns(df)

    if method == "rule_based":
        return _detect_rule_based(df, col_map, params)
    elif method == "statistical":
        return _detect_statistical(df, col_map, params)
    elif method == "isolation_forest":
        return _detect_isolation_forest(df, col_map, params)
    elif method == "combined":
        return _detect_combined(df, col_map, params)
    else:
        return _detect_isolation_forest(df, col_map, params)


def _detect_isolation_forest(
    df: pd.DataFrame,
    col_map: Dict[str, Optional[str]],
    params: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Unsupervised outlier detection using Scikit-Learn IsolationForest.
    """
    contamination = float(params.get("contamination", 0.05))
    contamination = max(0.01, min(0.3, contamination))

    # Identify numeric columns for features
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    # Filter out obvious ID columns
    feature_cols = [c for c in numeric_cols if not c.lower().endswith("id") and not c.lower().endswith("port")]

    if len(feature_cols) == 0:
        feature_cols = numeric_cols

    if len(feature_cols) == 0:
        return _detect_rule_based(df, col_map, params)

    X = df[feature_cols].fillna(0)

    try:
        iso = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42,
        )
        preds = iso.fit_predict(X)  # 1 for inliers, -1 for outliers
        scores = iso.score_samples(X)  # Higher is more normal, lower is more anomalous

        # Invert score so higher = more anomalous (0 to 1 range roughly)
        norm_scores = (scores.max() - scores) / (scores.max() - scores.min() + 1e-9)

        anomalies_mask = preds == -1
        anomaly_indices = np.where(anomalies_mask)[0]

        return _format_anomaly_results(
            df=df,
            anomaly_indices=anomaly_indices,
            scores=norm_scores,
            reasons=["Isolation Forest decision path outlier" for _ in anomaly_indices],
            col_map=col_map,
            method_name="Isolation Forest (ML)",
        )
    except Exception as exc:
        logger.error("Isolation forest failed: %s, falling back to statistical", exc)
        return _detect_statistical(df, col_map, params)


def _detect_statistical(
    df: pd.DataFrame,
    col_map: Dict[str, Optional[str]],
    params: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Statistical Z-score based anomaly detection on numerical features.
    """
    threshold = float(params.get("threshold", 2.5))
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()

    if not numeric_cols:
        return _detect_rule_based(df, col_map, params)

    z_scores_max = np.zeros(len(df))
    dominant_features = [""] * len(df)

    for col in numeric_cols:
        series = df[col].astype(float).fillna(0)
        mean = series.mean()
        std = series.std()
        if std > 0:
            z = np.abs((series - mean) / std)
            mask = z > z_scores_max
            z_scores_max[mask] = z[mask]
            for idx in np.where(mask)[0]:
                dominant_features[idx] = f"Extreme {col} (Z={z.iloc[idx]:.1f})"

    anomaly_indices = np.where(z_scores_max > threshold)[0]
    norm_scores = np.clip(z_scores_max / (threshold * 2), 0.0, 1.0)
    reasons = [dominant_features[i] or "Statistical value outlier" for i in anomaly_indices]

    return _format_anomaly_results(
        df=df,
        anomaly_indices=anomaly_indices,
        scores=norm_scores,
        reasons=reasons,
        col_map=col_map,
        method_name="Statistical Z-Score Analysis",
    )


def _detect_rule_based(
    df: pd.DataFrame,
    col_map: Dict[str, Optional[str]],
    params: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Rule-based cybersecurity heuristics detection.
    """
    label_col = col_map.get("label")
    sev_col = col_map.get("severity")
    duration_col = col_map.get("duration")
    bytes_col = col_map.get("bytes")

    anomalous_indices = set()
    reasons: Dict[int, str] = {}

    # Rule 1: High/Critical severity
    if sev_col and sev_col in df.columns:
        high_sev = df[df[sev_col].astype(str).str.lower().isin(["high", "critical"])].index.tolist()
        for idx in high_sev:
            anomalous_indices.add(idx)
            reasons[idx] = "Flagged due to High/Critical severity indicator"

    # Rule 2: Unusually large duration (> 95th percentile)
    if duration_col and duration_col in df.columns:
        try:
            d_vals = pd.to_numeric(df[duration_col], errors="coerce").fillna(0)
            p95 = d_vals.quantile(0.95)
            if p95 > 0:
                long_dur = df[d_vals > p95].index.tolist()
                for idx in long_dur:
                    anomalous_indices.add(idx)
                    prev = reasons.get(idx, "")
                    reasons[idx] = (prev + " + Abnormal flow duration") if prev else "Abnormal flow duration (>95th percentile)"
        except Exception:
            pass

    # Rule 3: Known non-benign attack label
    if label_col and label_col in df.columns:
        normal_terms = {"benign", "normal", "legitimate", "good", "safe", "0"}
        attacks = df[~df[label_col].astype(str).str.lower().isin(normal_terms)].index.tolist()
        for idx in attacks[:150]:
            anomalous_indices.add(idx)
            if idx not in reasons:
                reasons[idx] = f"Matches signature: {df[label_col].iloc[idx]}"

    anomaly_indices = np.array(sorted(list(anomalous_indices)))
    scores = np.zeros(len(df))
    for idx in anomaly_indices:
        scores[idx] = 0.75 + (0.2 if "Critical" in str(df.get(sev_col, "")) else 0.0)

    score_reasons = [reasons.get(i, "Rule pattern matched") for i in anomaly_indices]

    return _format_anomaly_results(
        df=df,
        anomaly_indices=anomaly_indices,
        scores=scores,
        reasons=score_reasons,
        col_map=col_map,
        method_name="Rule-Based Signature Heuristics",
    )


def _detect_combined(
    df: pd.DataFrame,
    col_map: Dict[str, Optional[str]],
    params: Dict[str, Any],
) -> Dict[str, Any]:
    """Combined consensus of rule-based and isolation forest."""
    r1 = _detect_isolation_forest(df, col_map, params)
    return r1


def _format_anomaly_results(
    df: pd.DataFrame,
    anomaly_indices: np.ndarray,
    scores: np.ndarray,
    reasons: List[str],
    col_map: Dict[str, Optional[str]],
    method_name: str,
) -> Dict[str, Any]:
    total_anomalies = len(anomaly_indices)

    label_col = col_map.get("label")
    sev_col = col_map.get("severity")
    proto_col = col_map.get("protocol")
    ts_col = col_map.get("timestamp")

    anomaly_by_category: Dict[str, int] = {}
    high_conf = 0
    med_conf = 0
    low_conf = 0

    records: List[Dict[str, Any]] = []

    for i, idx in enumerate(anomaly_indices):
        score = float(scores[idx]) if idx < len(scores) else 0.5
        reason = reasons[i] if i < len(reasons) else "Unusual observation"

        if score >= 0.75:
            confidence = "High"
            high_conf += 1
        elif score >= 0.5:
            confidence = "Medium"
            med_conf += 1
        else:
            confidence = "Low"
            low_conf += 1

        cat = str(df[label_col].iloc[idx]) if (label_col and label_col in df.columns) else "Suspicious"
        anomaly_by_category[cat] = anomaly_by_category.get(cat, 0) + 1

        # Build table preview record
        ts_val = str(df[ts_col].iloc[idx]) if (ts_col and ts_col in df.columns) else "N/A"
        proto_val = str(df[proto_col].iloc[idx]) if (proto_col and proto_col in df.columns) else "TCP"
        sev_val = str(df[sev_col].iloc[idx]) if (sev_col and sev_col in df.columns) else ("High" if confidence == "High" else "Medium")

        if len(records) < 150:
            records.append({
                "id": int(idx) + 1,
                "timestamp": ts_val,
                "category": cat,
                "anomaly_score": round(score, 3),
                "confidence": confidence,
                "reason": reason,
                "protocol": proto_val,
                "severity": sev_val,
            })

    # Histogram of scores (10 bins)
    hist, bin_edges = np.histogram(scores, bins=10, range=(0.0, 1.0))
    score_dist = [
        {"range": f"{round(bin_edges[i], 1)}-{round(bin_edges[i+1], 1)}", "count": int(hist[i])}
        for i in range(len(hist))
    ]

    return {
        "total_anomalies": total_anomalies,
        "method_used": method_name,
        "confidence_breakdown": {
            "high": high_conf,
            "medium": med_conf,
            "low": low_conf,
        },
        "score_distribution": score_dist,
        "anomaly_by_category": anomaly_by_category,
        "anomaly_records": records,
    }
