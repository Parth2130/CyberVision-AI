"""
CyberVision AI – Unit and Integration Tests
Tests data loading, preprocessing, analytical engine, anomaly detection, and FastAPI endpoints.
"""

import sys
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

import pandas as pd
import pytest
from services.data_loader import detect_columns, validate_dataframe, get_sample_data
from services.data_cleaner import clean_dataframe, get_cleaning_report
from services.analysis_service import analyze_dataset, apply_filters
from services.anomaly_service import detect_anomalies
from services.report_service import generate_csv, generate_json


@pytest.fixture
def sample_df():
    return pd.DataFrame({
        "timestamp": ["2026-10-19 08:00:00", "2026-10-19 09:00:00", "2026-10-19 10:00:00"],
        "label": ["BENIGN", "DoS Hulk", "PortScan"],
        "protocol": ["TCP", "TCP", "UDP"],
        "src_ip": ["192.168.1.10", "45.33.32.156", "185.220.101.5"],
        "dst_ip": ["142.250.190.46", "192.168.1.10", "192.168.1.15"],
        "severity": ["Low", "High", "Medium"],
        "duration": [12.5, 185.2, 0.5],
        "total_bytes": [12450, 425100, 128],
    })


def test_validate_dataframe(sample_df):
    ok, msg = validate_dataframe(sample_df)
    assert ok is True
    assert msg == ""

    # Test empty dataframe rejection
    ok_empty, _ = validate_dataframe(pd.DataFrame())
    assert ok_empty is False


def test_detect_columns(sample_df):
    col_map = detect_columns(sample_df)
    assert col_map["label"] == "label"
    assert col_map["protocol"] == "protocol"
    assert col_map["src_ip"] == "src_ip"
    assert col_map["severity"] == "severity"


def test_clean_dataframe(sample_df):
    col_map = detect_columns(sample_df)
    cleaned = clean_dataframe(sample_df, col_map)
    assert len(cleaned) == 3
    report = get_cleaning_report(sample_df, cleaned)
    assert report["cleaned_rows"] == 3


def test_analyze_dataset(sample_df):
    col_map = detect_columns(sample_df)
    analysis = analyze_dataset(sample_df, col_map)
    assert analysis["summary"]["total_records"] == 3
    assert analysis["summary"]["normal_records"] == 1
    assert analysis["summary"]["attack_records"] == 2
    assert "DoS Hulk" in analysis["categories"]["distribution"]


def test_apply_filters(sample_df):
    filtered = apply_filters(sample_df, {"category": "DoS Hulk"})
    assert len(filtered) == 1
    assert filtered.iloc[0]["label"] == "DoS Hulk"


def test_anomaly_detection(sample_df):
    anomalies = detect_anomalies(sample_df, method="rule_based")
    assert "total_anomalies" in anomalies
    assert anomalies["method_used"] == "Rule-Based Signature Heuristics"


def test_report_service(sample_df):
    csv_bytes = generate_csv(sample_df)
    assert isinstance(csv_bytes, bytes)
    assert b"DoS Hulk" in csv_bytes

    analysis = analyze_dataset(sample_df)
    json_str = generate_json(analysis)
    assert isinstance(json_str, str)
    assert "total_records" in json_str
