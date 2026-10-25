"""
CyberVision AI - Cybersecurity Data Analysis & Visualization Platform
FastAPI Backend Application
"""

import io
import math
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("cybervision-api")

# Directory Configuration
BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_DIR.parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"
DATA_DIR = PROJECT_ROOT / "data"
SAMPLE_CSV_PATH = DATA_DIR / "sample_cybersecurity.csv"
MAX_UPLOAD_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB limit

app = FastAPI(
    title="CyberVision AI API",
    description="Cybersecurity Data Analysis, Anomaly Detection & Visualization Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-Memory Active Dataset State (Browser-local session oriented)
_active_session: Dict[str, Any] = {
    "df": None,
    "filename": None,
    "file_size_bytes": 0,
    "uploaded_at": None,
    "is_sample": False,
    "analysis_result": None,
}

# Standard Port Reference Dictionary for Traffic Analysis
KNOWN_PORTS: Dict[int, str] = {
    20: "FTP-Data",
    21: "FTP-Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MS-SQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

# Flexible Column Recognition Aliases
COLUMN_PATTERNS = {
    "timestamp": ["timestamp", "time", "datetime", "date", "event_time", "logged_at", "ts"],
    "source_ip": ["source_ip", "src_ip", "sourceip", "srcip", "source_address", "src_addr", "src", "origin_ip"],
    "destination_ip": ["destination_ip", "dst_ip", "dest_ip", "destinationip", "dstip", "dest_addr", "dst_addr", "dst", "target_ip"],
    "source_port": ["source_port", "src_port", "sport", "sourceport", "srcport"],
    "destination_port": ["destination_port", "dst_port", "dest_port", "dport", "destinationport", "dstport", "target_port"],
    "protocol": ["protocol", "proto", "transport_protocol", "net_protocol"],
    "bytes_transferred": ["bytes_transferred", "total_bytes", "bytes", "byte_count", "tot_bytes", "tot_byte", "length", "octets"],
    "packets": ["packets", "packet_count", "tot_packets", "total_packets", "fwd_packets", "pkts", "packet_total"],
    "attack_type": ["attack_type", "attack", "threat_type", "threat_name", "label", "classification", "category", "class"],
    "severity": ["severity", "threat_level", "risk_level", "priority", "alert_level", "risk"],
    "event_type": ["event_type", "event", "action", "activity", "description", "signature", "event_name"],
    "login_attempts": ["login_attempts", "logins", "auth_attempts", "attempts"],
    "failed_login_attempts": ["failed_login_attempts", "failed_logins", "login_failures", "failed_attempts"],
    "status": ["status", "disposition", "action_taken", "result", "outcome"],
}


def sanitize_val(val: Any) -> Any:
    """Safely sanitize NaN, Inf, and non-serializable objects for JSON."""
    if val is None:
        return None
    if isinstance(val, (float, np.floating)):
        if math.isnan(val) or math.isinf(val):
            return None
        return float(val)
    if isinstance(val, (int, np.integer)):
        return int(val)
    if isinstance(val, (datetime, pd.Timestamp)):
        return val.isoformat()
    return val


def detect_columns(df: pd.DataFrame) -> Dict[str, Optional[str]]:
    """Detect available security columns by matching aliases case-insensitively."""
    detected: Dict[str, Optional[str]] = {}
    normalized_cols = {col.strip().lower().replace("-", "_").replace(" ", "_"): col for col in df.columns}

    for standard_key, aliases in COLUMN_PATTERNS.items():
        matched_col = None
        for alias in aliases:
            if alias in normalized_cols:
                matched_col = normalized_cols[alias]
                break
        detected[standard_key] = matched_col

    return detected


def normalize_severity(val: Any) -> str:
    """Normalize severity labels to standard levels."""
    if pd.isna(val):
        return "Unknown"
    s = str(val).strip().lower()
    if s in ["critical", "crit", "sev1", "p1", "very high", "urgent"]:
        return "Critical"
    elif s in ["high", "sev2", "p2", "elevated", "major"]:
        return "High"
    elif s in ["medium", "med", "sev3", "p3", "moderate", "warning"]:
        return "Medium"
    elif s in ["low", "sev4", "p4", "minor", "notice"]:
        return "Low"
    elif s in ["info", "informational", "sev5", "p5", "debug", "normal", "benign"]:
        return "Informational"
    else:
        return str(val).strip().capitalize()


def analyze_dataframe(df: pd.DataFrame, filename: str, file_size_bytes: int, is_sample: bool = False) -> Dict[str, Any]:
    """
    Perform comprehensive, safe analysis on a cybersecurity dataset.
    Returns structured results for overview, explorer, threat analytics,
    traffic analysis, interactive charts, and report generation.
    """
    row_count = int(len(df))
    col_count = int(len(df.columns))
    col_map = detect_columns(df)

    # 1. Missing Values & Hygiene
    missing_by_col = {str(col): int(df[col].isna().sum()) for col in df.columns}
    total_missing_cells = int(df.isna().sum().sum())
    duplicate_rows = int(df.duplicated().sum())

    # Data types breakdown
    column_dtypes = {str(col): str(df[col].dtype) for col in df.columns}

    # 2. General Numeric Summaries
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    numeric_summary: Dict[str, Dict[str, Any]] = {}
    for ncol in numeric_cols[:10]:  # limit to top 10 numeric
        series = df[ncol].dropna()
        if not series.empty:
            numeric_summary[str(ncol)] = {
                "min": sanitize_val(series.min()),
                "max": sanitize_val(series.max()),
                "mean": sanitize_val(round(float(series.mean()), 2)),
                "median": sanitize_val(round(float(series.median()), 2)),
                "std": sanitize_val(round(float(series.std()), 2)) if len(series) > 1 else 0.0,
            }

    # 3. Traffic Analysis
    traffic_available = False
    source_ips_summary: Dict[str, Any] = {"available": False, "unique_count": 0, "top_sources": []}
    dest_ips_summary: Dict[str, Any] = {"available": False, "unique_count": 0, "top_destinations": []}
    protocols_summary: Dict[str, Any] = {"available": False, "breakdown": {}, "volume_by_protocol": {}}
    dest_ports_summary: Dict[str, Any] = {"available": False, "top_ports": []}
    bytes_summary: Dict[str, Any] = {"available": False, "total": 0, "mean": 0, "max": 0}
    packets_summary: Dict[str, Any] = {"available": False, "total": 0, "mean": 0, "max": 0}
    time_series_summary: Dict[str, Any] = {"available": False, "points": [], "interval": "hour"}

    src_col = col_map.get("source_ip")
    if src_col and src_col in df.columns:
        traffic_available = True
        src_series = df[src_col].dropna().astype(str)
        source_ips_summary["available"] = True
        source_ips_summary["unique_count"] = int(src_series.nunique())
        top_src = src_series.value_counts().head(10).to_dict()
        source_ips_summary["top_sources"] = [{"ip": k, "count": int(v)} for k, v in top_src.items()]

    dst_col = col_map.get("destination_ip")
    if dst_col and dst_col in df.columns:
        traffic_available = True
        dst_series = df[dst_col].dropna().astype(str)
        dest_ips_summary["available"] = True
        dest_ips_summary["unique_count"] = int(dst_series.nunique())
        top_dst = dst_series.value_counts().head(10).to_dict()
        dest_ips_summary["top_destinations"] = [{"ip": k, "count": int(v)} for k, v in top_dst.items()]

    proto_col = col_map.get("protocol")
    if proto_col and proto_col in df.columns:
        traffic_available = True
        protocols_summary["available"] = True
        proto_series = df[proto_col].dropna().astype(str).str.upper()
        protocols_summary["breakdown"] = {k: int(v) for k, v in proto_series.value_counts().items()}

        # Volume by protocol if bytes available
        bytes_col = col_map.get("bytes_transferred")
        if bytes_col and bytes_col in df.columns and pd.api.types.is_numeric_dtype(df[bytes_col]):
            vol = df.groupby(proto_series)[bytes_col].sum().to_dict()
            protocols_summary["volume_by_protocol"] = {str(k): int(v) for k, v in vol.items()}

    dst_port_col = col_map.get("destination_port")
    if dst_port_col and dst_port_col in df.columns and pd.api.types.is_numeric_dtype(df[dst_port_col]):
        traffic_available = True
        dest_ports_summary["available"] = True
        top_ports = df[dst_port_col].dropna().astype(int).value_counts().head(10).to_dict()
        dest_ports_summary["top_ports"] = [
            {"port": int(p), "name": KNOWN_PORTS.get(int(p), "Custom"), "count": int(c)}
            for p, c in top_ports.items()
        ]

    bytes_col = col_map.get("bytes_transferred")
    if bytes_col and bytes_col in df.columns and pd.api.types.is_numeric_dtype(df[bytes_col]):
        b_series = df[bytes_col].dropna()
        if not b_series.empty:
            bytes_summary["available"] = True
            bytes_summary["total"] = int(b_series.sum())
            bytes_summary["mean"] = round(float(b_series.mean()), 2)
            bytes_summary["max"] = int(b_series.max())

    pkts_col = col_map.get("packets")
    if pkts_col and pkts_col in df.columns and pd.api.types.is_numeric_dtype(df[pkts_col]):
        p_series = df[pkts_col].dropna()
        if not p_series.empty:
            packets_summary["available"] = True
            packets_summary["total"] = int(p_series.sum())
            packets_summary["mean"] = round(float(p_series.mean()), 2)
            packets_summary["max"] = int(p_series.max())

    # Timestamp series
    ts_col = col_map.get("timestamp")
    if ts_col and ts_col in df.columns:
        try:
            parsed_ts = pd.to_datetime(df[ts_col], errors="coerce").dropna()
            if not parsed_ts.empty and parsed_ts.nunique() > 1:
                time_range_hours = (parsed_ts.max() - parsed_ts.min()).total_seconds() / 3600.0
                freq = "10min" if time_range_hours <= 6 else ("1h" if time_range_hours <= 48 else "1D")
                ts_counts = parsed_ts.dt.floor(freq).value_counts().sort_index()
                time_series_summary["available"] = True
                time_series_summary["points"] = [
                    {"time": idx.strftime("%Y-%m-%d %H:%M"), "count": int(val)}
                    for idx, val in ts_counts.items()
                ]
                time_series_summary["interval"] = freq
        except Exception as e:
            logger.warning("Could not parse timestamp series: %s", e)

    # 4. Threat Analytics
    threat_available = False
    severity_summary: Dict[str, Any] = {"available": False, "distribution": {}, "high_critical_count": 0, "high_critical_pct": 0.0}
    attack_type_summary: Dict[str, Any] = {"available": False, "distribution": {}, "top_attacks": []}
    event_type_summary: Dict[str, Any] = {"available": False, "distribution": {}}
    suspicious_patterns: List[Dict[str, Any]] = []
    suspicious_records_count = 0

    sev_col = col_map.get("severity")
    if sev_col and sev_col in df.columns:
        threat_available = True
        severity_summary["available"] = True
        norm_sev = df[sev_col].apply(normalize_severity)
        sev_counts = norm_sev.value_counts().to_dict()
        severity_summary["distribution"] = {k: int(v) for k, v in sev_counts.items()}
        high_crit = int(sev_counts.get("Critical", 0) + sev_counts.get("High", 0))
        severity_summary["high_critical_count"] = high_crit
        severity_summary["high_critical_pct"] = round((high_crit / row_count) * 100, 1) if row_count > 0 else 0.0

    attack_col = col_map.get("attack_type")
    if attack_col and attack_col in df.columns:
        threat_available = True
        attack_type_summary["available"] = True
        atk_series = df[attack_col].dropna().astype(str).str.strip()
        atk_counts = atk_series.value_counts().to_dict()
        attack_type_summary["distribution"] = {k: int(v) for k, v in atk_counts.items()}
        attack_type_summary["top_attacks"] = [{"attack": k, "count": int(v)} for k, v in list(atk_counts.items())[:8]]

    event_col = col_map.get("event_type")
    if event_col and event_col in df.columns:
        threat_available = True
        event_type_summary["available"] = True
        ev_series = df[event_col].dropna().astype(str).str.strip()
        event_type_summary["distribution"] = {k: int(v) for k, v in ev_series.value_counts().head(8).items()}

    # Suspicious pattern rules
    flagged_indices = set()

    # Rule A: High or Critical severity
    if sev_col and sev_col in df.columns:
        norm_sev = df[sev_col].apply(normalize_severity)
        high_sev_idx = df[norm_sev.isin(["Critical", "High"])].index.tolist()
        for idx in high_sev_idx:
            flagged_indices.add(idx)
        if high_sev_idx:
            suspicious_patterns.append({
                "rule": "High & Critical Severity Security Events",
                "count": len(high_sev_idx),
                "description": f"Identified {len(high_sev_idx)} records explicitly tagged with Critical or High severity levels.",
                "severity": "Critical"
            })

    # Rule B: Non-benign attack labels
    if attack_col and attack_col in df.columns:
        non_benign = df[~df[attack_col].astype(str).str.strip().str.lower().isin(["benign", "normal", "none", "clean"])].index.tolist()
        for idx in non_benign:
            flagged_indices.add(idx)
        if non_benign:
            suspicious_patterns.append({
                "rule": "Flagged Threat Classifications",
                "count": len(non_benign),
                "description": f"Identified {len(non_benign)} records labeled with non-benign threat categories.",
                "severity": "High"
            })

    # Rule C: Failed logins threshold
    failed_logins_col = col_map.get("failed_login_attempts")
    if failed_logins_col and failed_logins_col in df.columns and pd.api.types.is_numeric_dtype(df[failed_logins_col]):
        fl_idx = df[df[failed_logins_col] >= 3].index.tolist()
        for idx in fl_idx:
            flagged_indices.add(idx)
        if fl_idx:
            suspicious_patterns.append({
                "rule": "Repeated Authentication Failures",
                "count": len(fl_idx),
                "description": f"Detected {len(fl_idx)} sessions with 3 or more failed login attempts (possible brute-force).",
                "severity": "High"
            })

    # Rule D: Port scan heuristics (single source probing >= 4 distinct destination ports)
    if src_col and dst_port_col and src_col in df.columns and dst_port_col in df.columns:
        port_counts_per_ip = df.groupby(src_col)[dst_port_col].nunique()
        scanner_ips = port_counts_per_ip[port_counts_per_ip >= 4].index.tolist()
        if scanner_ips:
            scanner_records = df[df[src_col].isin(scanner_ips)].index.tolist()
            for idx in scanner_records:
                flagged_indices.add(idx)
            suspicious_patterns.append({
                "rule": "Multi-Port Reconnaissance Pattern",
                "count": len(scanner_records),
                "description": f"{len(scanner_ips)} unique source IP(s) probed 4 or more distinct destination ports.",
                "severity": "Medium"
            })

    # Rule E: Statistical volume anomaly (> 98th percentile bytes transferred)
    if bytes_col and bytes_col in df.columns and pd.api.types.is_numeric_dtype(df[bytes_col]):
        b_series = df[bytes_col].dropna()
        if len(b_series) > 20:
            threshold_98 = b_series.quantile(0.98)
            vol_outliers = df[df[bytes_col] > threshold_98].index.tolist()
            if vol_outliers and threshold_98 > 10000:
                for idx in vol_outliers:
                    flagged_indices.add(idx)
                suspicious_patterns.append({
                    "rule": "High-Volume Data Transfer Anomaly",
                    "count": len(vol_outliers),
                    "description": f"{len(vol_outliers)} records exceeded the 98th percentile volume threshold ({threshold_98:,.0f} bytes).",
                    "severity": "Medium"
                })

    suspicious_records_count = len(flagged_indices)

    # 5. Dataset Preview (First 100 rows safely sanitized)
    preview_df = df.head(100).copy().reset_index(drop=True)
    preview_records = []
    for _, row in preview_df.iterrows():
        row_dict = {}
        for col in preview_df.columns:
            val = row[col]
            row_dict[str(col)] = sanitize_val(val)
        preview_records.append(row_dict)

    # 6. Overall Summary Metrics
    overview_metrics = {
        "total_records": row_count,
        "total_columns": col_count,
        "unique_source_ips": source_ips_summary["unique_count"] if source_ips_summary["available"] else None,
        "unique_dest_ips": dest_ips_summary["unique_count"] if dest_ips_summary["available"] else None,
        "high_severity_events": severity_summary["high_critical_count"] if severity_summary["available"] else None,
        "missing_values_count": total_missing_cells,
        "duplicate_records_count": duplicate_rows,
        "suspicious_records_count": suspicious_records_count if (threat_available or len(suspicious_patterns) > 0) else None,
    }

    # 7. Quality Findings
    quality_findings = []
    if total_missing_cells == 0:
        quality_findings.append({"status": "healthy", "title": "Zero Missing Values", "desc": "All fields in this dataset are fully populated with no missing values."})
    else:
        quality_findings.append({"status": "warning", "title": f"{total_missing_cells} Missing Cell(s)", "desc": "Missing data detected across some attributes; imputed or handled in summaries."})

    if duplicate_rows == 0:
        quality_findings.append({"status": "healthy", "title": "No Duplicate Records", "desc": "Every row in the dataset represents a distinct event signature."})
    else:
        quality_findings.append({"status": "info", "title": f"{duplicate_rows} Duplicate Record(s)", "desc": "Duplicate rows detected. Retained for realistic event frequency fidelity."})

    return {
        "metadata": {
            "filename": filename,
            "file_size": file_size_bytes,
            "file_size_formatted": f"{file_size_bytes / 1024:.1f} KB" if file_size_bytes > 0 else "N/A",
            "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "is_sample": is_sample,
            "validation_status": "Valid CSV • Processed Successfully",
        },
        "overview_metrics": overview_metrics,
        "detected_columns": col_map,
        "missing_by_col": missing_by_col,
        "column_dtypes": column_dtypes,
        "numeric_summary": numeric_summary,
        "traffic_analysis": {
            "available": traffic_available,
            "source_ips": source_ips_summary,
            "dest_ips": dest_ips_summary,
            "protocols": protocols_summary,
            "dest_ports": dest_ports_summary,
            "bytes": bytes_summary,
            "packets": packets_summary,
            "time_series": time_series_summary,
        },
        "threat_analytics": {
            "available": threat_available,
            "severity": severity_summary,
            "attack_types": attack_type_summary,
            "event_types": event_type_summary,
            "suspicious_patterns": suspicious_patterns,
            "suspicious_records_count": suspicious_records_count,
        },
        "quality_findings": quality_findings,
        "preview_records": preview_records,
        "columns": [str(c) for c in df.columns],
    }


# ==============================================================================
# API Endpoints
# ==============================================================================

@app.get("/health", tags=["System"])
async def health_check() -> Dict[str, Any]:
    """Health check endpoint confirming backend operational status."""
    return {
        "status": "healthy",
        "app": "CyberVision AI",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat(),
        "dataset_loaded": _active_session["df"] is not None,
    }


@app.get("/api/status", tags=["Dataset"])
async def get_dataset_status() -> Dict[str, Any]:
    """Retrieve the current in-memory dataset status."""
    if _active_session["df"] is None:
        return {
            "loaded": False,
            "message": "No dataset currently loaded in session.",
        }
    return {
        "loaded": True,
        "filename": _active_session["filename"],
        "is_sample": _active_session["is_sample"],
        "uploaded_at": _active_session["uploaded_at"],
        "rows": len(_active_session["df"]),
        "columns": len(_active_session["df"].columns),
        "analysis_cached": _active_session["analysis_result"] is not None,
    }


@app.get("/api/sample", tags=["Dataset"])
async def get_sample_dataset(download: bool = Query(False)) -> Any:
    """
    Access or download the synthetic demonstration dataset.
    If download=True, returns sample_cybersecurity.csv as an attachment.
    Otherwise, returns sample file metadata.
    """
    if not SAMPLE_CSV_PATH.exists():
        raise HTTPException(status_code=404, detail="Sample dataset file not found on server.")

    if download:
        return FileResponse(
            path=str(SAMPLE_CSV_PATH),
            media_type="text/csv",
            filename="sample_cybersecurity.csv",
        )

    file_size = SAMPLE_CSV_PATH.stat().st_size
    return {
        "filename": "sample_cybersecurity.csv",
        "size_bytes": file_size,
        "size_formatted": f"{file_size / 1024:.1f} KB",
        "path": "/api/sample?download=true",
        "description": "Pre-packaged synthetic cybersecurity dataset with normal and anomalous network events.",
    }


@app.post("/api/analyze", tags=["Analysis"])
async def analyze_dataset_endpoint(
    file: Optional[UploadFile] = File(None),
    use_sample: bool = Form(False),
) -> JSONResponse:
    """
    Accept an uploaded CSV file or load the built-in sample dataset.
    Validates CSV, detects columns, performs statistical and threat analysis,
    and returns comprehensive chart-ready payloads.
    """
    try:
        df: Optional[pd.DataFrame] = None
        filename: str = ""
        file_size_bytes: int = 0
        is_sample: bool = False

        if use_sample or (file is None and not _active_session.get("df")):
            # Load the sample dataset
            if not SAMPLE_CSV_PATH.exists():
                raise HTTPException(status_code=404, detail="Sample dataset file not found on server.")
            df = pd.read_csv(SAMPLE_CSV_PATH)
            filename = "sample_cybersecurity.csv"
            file_size_bytes = SAMPLE_CSV_PATH.stat().st_size
            is_sample = True
            logger.info("Loaded built-in sample dataset (%d rows)", len(df))

        elif file is not None:
            # Validate filename and extension
            filename = file.filename or "uploaded_dataset.csv"
            if not filename.lower().endswith(".csv"):
                raise HTTPException(status_code=400, detail="Invalid file type. Only CSV (.csv) files are supported.")

            content = await file.read()
            file_size_bytes = len(content)

            if file_size_bytes == 0:
                raise HTTPException(status_code=400, detail="The uploaded file is empty. Please upload a valid CSV.")

            if file_size_bytes > MAX_UPLOAD_SIZE_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail=f"File exceeds maximum allowable limit of {MAX_UPLOAD_SIZE_BYTES / (1024*1024):.0f}MB."
                )

            # Attempt multi-encoding decode safely
            decoded_df = None
            last_err = None
            for encoding in ("utf-8", "latin-1", "cp1252", "iso-8859-1"):
                try:
                    decoded_df = pd.read_csv(io.BytesIO(content), encoding=encoding)
                    break
                except UnicodeDecodeError:
                    continue
                except pd.errors.EmptyDataError:
                    raise HTTPException(status_code=400, detail="The uploaded CSV contains no data or column headers.")
                except Exception as ex:
                    last_err = str(ex)
                    break

            if decoded_df is None:
                raise HTTPException(
                    status_code=422,
                    detail=f"Unable to parse CSV file: {last_err or 'Invalid encoding format.'}"
                )

            df = decoded_df
            is_sample = False
            logger.info("Successfully parsed uploaded CSV '%s' with %d rows and %d columns", filename, len(df), len(df.columns))

        elif _active_session.get("df") is not None:
            # Re-analyze currently loaded dataset
            df = _active_session["df"]
            filename = _active_session["filename"]
            file_size_bytes = _active_session["file_size_bytes"]
            is_sample = _active_session["is_sample"]

        else:
            raise HTTPException(status_code=400, detail="No CSV file provided and no active dataset in session.")

        if df.empty or len(df.columns) == 0:
            raise HTTPException(status_code=400, detail="Dataset is empty or contains no detectable columns.")

        # Run analysis pipeline
        analysis_result = analyze_dataframe(df, filename=filename, file_size_bytes=file_size_bytes, is_sample=is_sample)

        # Update in-memory session
        _active_session["df"] = df
        _active_session["filename"] = filename
        _active_session["file_size_bytes"] = file_size_bytes
        _active_session["uploaded_at"] = datetime.now().isoformat()
        _active_session["is_sample"] = is_sample
        _active_session["analysis_result"] = analysis_result

        return JSONResponse(content={
            "success": True,
            "message": f"Successfully analyzed {len(df):,} records from '{filename}'.",
            "data": analysis_result,
        })

    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Unexpected error during dataset analysis: %s", exc)
        raise HTTPException(status_code=500, detail=f"Analysis pipeline error: {str(exc)}")


class ReportRequest(BaseModel):
    format: str = "json"  # "json" or "csv"


@app.post("/api/report", tags=["Reports"])
async def generate_report_endpoint(req: ReportRequest) -> Any:
    """
    Generate and download a comprehensive analysis report in JSON or CSV format.
    Calculates metrics directly from the currently active dataset.
    """
    df = _active_session.get("df")
    analysis = _active_session.get("analysis_result")

    if df is None or analysis is None:
        raise HTTPException(status_code=400, detail="No active dataset loaded to generate report. Upload or load sample data first.")

    report_format = req.format.lower().strip()
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")

    if report_format == "json":
        report_payload = {
            "report_title": "CyberVision AI - Cybersecurity Dataset Analysis Report",
            "generated_at": datetime.now().isoformat(),
            "platform_version": "1.0.0",
            "dataset_metadata": analysis["metadata"],
            "dataset_summary_metrics": analysis["overview_metrics"],
            "column_detection_mapping": analysis["detected_columns"],
            "data_quality_audit": {
                "missing_values_by_column": analysis["missing_by_col"],
                "total_missing_cells": analysis["overview_metrics"]["missing_values_count"],
                "duplicate_rows": analysis["overview_metrics"]["duplicate_records_count"],
                "quality_findings": analysis["quality_findings"],
            },
            "threat_analytics_findings": analysis["threat_analytics"],
            "traffic_analytics_findings": analysis["traffic_analysis"],
            "numerical_distribution_statistics": analysis["numeric_summary"],
            "analysis_limitations": [
                "This report reflects static batch analysis of the uploaded dataset and is not a real-time monitoring feed.",
                "Heuristic pattern detections are rule-based indicators and do not constitute certified digital forensics or incident confirmation.",
                "Dataset columns were dynamically mapped based on header aliases; unmapped columns are omitted from domain-specific cards.",
            ]
        }
        return JSONResponse(
            content=report_payload,
            headers={"Content-Disposition": f'attachment; filename="cybervision_report_{timestamp_str}.json"'}
        )

    elif report_format in ["csv", "summary"]:
        # Build structured CSV summary
        output = io.StringIO()
        output.write("# CyberVision AI - Dataset Analysis Summary Report\n")
        output.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        output.write(f"# Source File: {analysis['metadata']['filename']}\n")
        output.write(f"# Total Records: {analysis['overview_metrics']['total_records']}\n")
        output.write(f"# Total Columns: {analysis['overview_metrics']['total_columns']}\n")
        output.write("# --------------------------------------------------\n\n")

        output.write("METRIC_CATEGORY,METRIC_NAME,METRIC_VALUE\n")
        for k, v in analysis["overview_metrics"].items():
            output.write(f"Overview,{k},{v if v is not None else 'N/A'}\n")

        # Threat severity
        if analysis["threat_analytics"]["available"]:
            for sev, count in analysis["threat_analytics"]["severity"]["distribution"].items():
                output.write(f"Threat Severity,{sev},{count}\n")
            for atk in analysis["threat_analytics"]["attack_types"]["top_attacks"]:
                output.write(f"Top Attacks,{atk['attack']},{atk['count']}\n")

        # Protocols
        if analysis["traffic_analysis"]["available"]:
            for proto, count in analysis["traffic_analysis"]["protocols"]["breakdown"].items():
                output.write(f"Protocols,{proto},{count}\n")
            for src in analysis["traffic_analysis"]["source_ips"]["top_sources"]:
                output.write(f"Top Source IP,{src['ip']},{src['count']}\n")

        csv_bytes = output.getvalue().encode("utf-8")
        return Response(
            content=csv_bytes,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="cybervision_summary_{timestamp_str}.csv"'}
        )

    else:
        raise HTTPException(status_code=400, detail="Unsupported report format requested. Choose 'json' or 'csv'.")


@app.post("/api/clear", tags=["Dataset"])
async def clear_active_dataset() -> Dict[str, Any]:
    """Clear the currently loaded dataset from active server session."""
    _active_session["df"] = None
    _active_session["filename"] = None
    _active_session["file_size_bytes"] = 0
    _active_session["uploaded_at"] = None
    _active_session["is_sample"] = False
    _active_session["analysis_result"] = None
    logger.info("Cleared active dataset session.")
    return {
        "success": True,
        "message": "Dataset cleared from active session successfully."
    }


# ==============================================================================
# Frontend Single-Page Serving
# ==============================================================================

@app.get("/", tags=["Frontend"])
async def serve_index() -> FileResponse:
    """Serve the single-page dashboard HTML application."""
    index_file = FRONTEND_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="Frontend index.html not found.")
    return FileResponse(index_file)


# Route root /style.css and /script.js directly for convenience
@app.get("/style.css", tags=["Frontend"])
async def serve_css() -> FileResponse:
    css_file = FRONTEND_DIR / "style.css"
    if not css_file.exists():
        raise HTTPException(status_code=404, detail="style.css not found.")
    return FileResponse(css_file, media_type="text/css")


@app.get("/script.js", tags=["Frontend"])
async def serve_js() -> FileResponse:
    js_file = FRONTEND_DIR / "script.js"
    if not js_file.exists():
        raise HTTPException(status_code=404, detail="script.js not found.")
    return FileResponse(js_file, media_type="application/javascript")


# Mount the frontend directory under /static for assets
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
