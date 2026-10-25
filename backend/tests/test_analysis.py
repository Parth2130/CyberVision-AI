"""
CyberVision AI - Comprehensive Backend & Analytical Engine Tests
"""

import io
import sys
from pathlib import Path
import pytest
import pandas as pd
from fastapi.testclient import TestClient

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.main import (
    app,
    detect_columns,
    normalize_severity,
    analyze_dataframe,
    SAMPLE_CSV_PATH
)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def sample_test_df():
    return pd.DataFrame({
        "timestamp": ["2026-10-24 08:00:00", "2026-10-24 08:01:00", "2026-10-24 08:02:00", "2026-10-24 08:03:00"],
        "source_ip": ["192.168.1.10", "45.33.32.156", "185.220.101.5", "91.240.118.23"],
        "destination_ip": ["142.250.190.46", "192.168.1.10", "192.168.1.15", "10.0.0.5"],
        "source_port": [52000, 54321, 41001, 49910],
        "destination_port": [443, 80, 22, 22],
        "protocol": ["TCP", "TCP", "TCP", "TCP"],
        "bytes_transferred": [14000, 420000, 128, 72000],
        "packets": [16, 320, 1, 95],
        "attack_type": ["Benign", "DoS Hulk", "PortScan", "SSH Brute Force"],
        "severity": ["Low", "High", "Medium", "High"],
        "event_type": ["Normal Traffic", "HTTP Flood", "Reconnaissance", "Authentication Attack"],
        "failed_login_attempts": [0, 0, 0, 45],
    })


def test_health_endpoint(client):
    """Test health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["app"] == "CyberVision AI"
    assert data["version"] == "1.0.0"


def test_detect_columns(sample_test_df):
    """Test flexible column alias detection."""
    detected = detect_columns(sample_test_df)
    assert detected["source_ip"] == "source_ip"
    assert detected["destination_ip"] == "destination_ip"
    assert detected["protocol"] == "protocol"
    assert detected["attack_type"] == "attack_type"
    assert detected["severity"] == "severity"
    assert detected["bytes_transferred"] == "bytes_transferred"
    assert detected["failed_login_attempts"] == "failed_login_attempts"


def test_normalize_severity():
    """Test standard normalization of severity values."""
    assert normalize_severity("CRITICAL") == "Critical"
    assert normalize_severity("high") == "High"
    assert normalize_severity("sev2") == "High"
    assert normalize_severity("medium") == "Medium"
    assert normalize_severity("low") == "Low"
    assert normalize_severity("informational") == "Informational"
    assert normalize_severity("benign") == "Informational"


def test_analyze_dataframe_sample():
    """Test analysis on actual packaged sample dataset."""
    assert SAMPLE_CSV_PATH.exists()
    df = pd.read_csv(SAMPLE_CSV_PATH)
    res = analyze_dataframe(df, "sample_cybersecurity.csv", 1000, is_sample=True)

    assert res["metadata"]["is_sample"] is True
    assert res["overview_metrics"]["total_records"] > 0
    assert res["overview_metrics"]["total_columns"] >= 10
    assert res["threat_analytics"]["available"] is True
    assert res["traffic_analysis"]["available"] is True
    assert len(res["preview_records"]) > 0


def test_analyze_dataframe_missing_threat_columns():
    """Test graceful handling when dataset lacks threat-specific columns."""
    minimal_df = pd.DataFrame({
        "device_id": [1, 2, 3],
        "reading": [10.5, 20.3, 15.8],
    })
    res = analyze_dataframe(minimal_df, "iot_readings.csv", 500)

    assert res["overview_metrics"]["total_records"] == 3
    assert res["overview_metrics"]["total_columns"] == 2
    assert res["threat_analytics"]["available"] is False
    assert res["traffic_analysis"]["available"] is False
    assert res["overview_metrics"]["high_severity_events"] is None


def test_api_sample_endpoint(client):
    """Test GET /api/sample endpoint."""
    res = client.get("/api/sample")
    assert res.status_code == 200
    data = res.json()
    assert data["filename"] == "sample_cybersecurity.csv"

    # Test file download
    dl_res = client.get("/api/sample?download=true")
    assert dl_res.status_code == 200
    assert "text/csv" in dl_res.headers.get("content-type", "")
    assert b"timestamp,source_ip,destination_ip" in dl_res.content


def test_api_analyze_use_sample(client):
    """Test POST /api/analyze with use_sample=True."""
    res = client.post("/api/analyze", data={"use_sample": "true"})
    assert res.status_code == 200
    body = res.json()
    assert body["success"] is True
    assert "data" in body
    assert body["data"]["overview_metrics"]["total_records"] > 0


def test_api_analyze_upload_custom_csv(client, sample_test_df):
    """Test POST /api/analyze with uploaded CSV file."""
    csv_bytes = sample_test_df.to_csv(index=False).encode("utf-8")
    files = {"file": ("custom_security_test.csv", io.BytesIO(csv_bytes), "text/csv")}
    res = client.post("/api/analyze", files=files)
    assert res.status_code == 200
    body = res.json()
    assert body["success"] is True
    assert body["data"]["metadata"]["filename"] == "custom_security_test.csv"
    assert body["data"]["overview_metrics"]["total_records"] == 4


def test_api_report_generation(client):
    """Test POST /api/report for JSON and CSV generation."""
    # First ensure a dataset is active
    client.post("/api/analyze", data={"use_sample": "true"})

    # Test JSON report
    json_res = client.post("/api/report", json={"format": "json"})
    assert json_res.status_code == 200
    json_report = json_res.json()
    assert "report_title" in json_report
    assert "dataset_summary_metrics" in json_report

    # Test CSV report
    csv_res = client.post("/api/report", json={"format": "csv"})
    assert csv_res.status_code == 200
    assert b"METRIC_CATEGORY,METRIC_NAME,METRIC_VALUE" in csv_res.content


def test_api_clear_dataset(client):
    """Test POST /api/clear endpoint."""
    res = client.post("/api/clear")
    assert res.status_code == 200
    assert res.json()["success"] is True

    # Check status endpoint
    status_res = client.get("/api/status")
    assert status_res.status_code == 200
    assert status_res.json()["loaded"] is False
