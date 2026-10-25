"""
CyberVision AI - FastAPI Backend
Main application entry point
"""

import os
import json
import logging
from pathlib import Path
from typing import Optional, List

import pandas as pd
from fastapi import FastAPI, File, UploadFile, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
import aiofiles

from services.data_loader import load_csv, detect_columns, get_sample_data, validate_dataframe
from services.data_cleaner import clean_dataframe, get_cleaning_report
from services.analysis_service import analyze_dataset, apply_filters, get_attack_comparison
from services.anomaly_service import detect_anomalies
from services.report_service import generate_csv, generate_pdf, generate_json

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("cybervision")

# App configuration
BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
DATA_DIR = BASE_DIR.parent / "data"

# Global state (in-memory session state; replace with DB for production)
_state: dict = {
    "df": None,
    "cleaned_df": None,
    "column_map": None,
    "analysis": None,
    "filename": None,
    "file_size": None,
}

app = FastAPI(
    title="CyberVision AI API",
    description="Network intrusion detection and analysis backend",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Startup / Shutdown
# ---------------------------------------------------------------------------
@app.on_event("startup")
async def startup_event() -> None:
    """Create necessary directories on startup."""
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    logger.info("CyberVision AI backend started. Upload dir: %s", UPLOAD_DIR)


# ---------------------------------------------------------------------------
# Exception handlers
# ---------------------------------------------------------------------------
@app.exception_handler(404)
async def not_found_handler(request: Request, exc) -> JSONResponse:
    return JSONResponse(status_code=404, content={"error": "Endpoint not found", "path": str(request.url)})


@app.exception_handler(500)
async def internal_error_handler(request: Request, exc) -> JSONResponse:
    logger.exception("Internal server error")
    return JSONResponse(status_code=500, content={"error": "Internal server error"})


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
@app.get("/health", tags=["Health"])
async def health_check() -> dict:
    """Health check endpoint."""
    return {"status": "ok", "version": "1.0.0"}


# ---------------------------------------------------------------------------
# Helper: require loaded data
# ---------------------------------------------------------------------------
def _require_data() -> tuple:
    """Return (cleaned_df, column_map) or raise 400."""
    df = _state.get("cleaned_df")
    col_map = _state.get("column_map")
    if df is None:
        raise HTTPException(status_code=400, detail="No dataset loaded. POST /api/upload first.")
    return df, col_map


# ---------------------------------------------------------------------------
# Upload & analyse
# ---------------------------------------------------------------------------
@app.post("/api/upload", tags=["Data"])
async def upload_file(file: Optional[UploadFile] = File(None)) -> JSONResponse:
    """
    Upload a CSV file and run the initial analysis pipeline.

    If no file is provided the built-in sample dataset is used.
    """
    try:
        if file is None:
            # Use sample data
            logger.info("No file provided – loading sample dataset")
            df = get_sample_data()
            filename = "sample_dataset.csv"
            file_size = "N/A (sample)"
        else:
            filename = file.filename or "upload.csv"
            dest = UPLOAD_DIR / filename
            content = await file.read()
            file_size = f"{len(content) / 1024:.1f} KB"
            async with aiofiles.open(dest, "wb") as f:
                await f.write(content)
            df, err = validate_dataframe_from_bytes(content)
            if df is None:
                raise HTTPException(status_code=422, detail=err)

        # Detect columns
        column_map = detect_columns(df)

        # Clean
        cleaned_df = clean_dataframe(df, column_map)
        cleaning_report = get_cleaning_report(df, cleaned_df)

        # Analyse
        analysis = analyze_dataset(cleaned_df, column_map)
        analysis["dataset_info"]["filename"] = filename
        analysis["dataset_info"]["file_size"] = file_size

        # Store state
        _state["df"] = df
        _state["cleaned_df"] = cleaned_df
        _state["column_map"] = column_map
        _state["analysis"] = analysis
        _state["filename"] = filename
        _state["file_size"] = file_size

        return JSONResponse(content={
            "success": True,
            "message": "Dataset loaded and analysed successfully",
            "cleaning_report": cleaning_report,
            "analysis": analysis,
        })

    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Error during upload")
        raise HTTPException(status_code=500, detail=str(exc))


def validate_dataframe_from_bytes(content: bytes):
    """Parse bytes to DataFrame and validate."""
    import io
    try:
        for enc in ("utf-8", "latin-1", "cp1252"):
            try:
                df = pd.read_csv(io.BytesIO(content), encoding=enc)
                ok, msg = validate_dataframe(df)
                if not ok:
                    return None, msg
                return df, None
            except UnicodeDecodeError:
                continue
        return None, "Could not decode file with any supported encoding"
    except Exception as exc:
        return None, str(exc)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@app.get("/api/dashboard", tags=["Analysis"])
async def get_dashboard() -> JSONResponse:
    """Return the current analysis summary."""
    _, _ = _require_data()
    analysis = _state.get("analysis")
    if analysis is None:
        raise HTTPException(status_code=400, detail="Analysis not available")
    return JSONResponse(content=analysis)


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------
@app.post("/api/anomaly", tags=["Analysis"])
async def run_anomaly_detection(body: dict = None) -> JSONResponse:
    """
    Run anomaly detection.

    Body (optional JSON):
    ```json
    {
        "method": "isolation_forest",   // or "rule_based" / "statistical"
        "params": {"contamination": 0.05, "threshold": 2.5}
    }
    ```
    """
    df, col_map = _require_data()
    if body is None:
        body = {}
    method = body.get("method", "isolation_forest")
    params = body.get("params", {})
    try:
        result = detect_anomalies(df, method=method, params=params)
        return JSONResponse(content=result)
    except Exception as exc:
        logger.exception("Anomaly detection failed")
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Reports – CSV
# ---------------------------------------------------------------------------
@app.get("/api/reports/csv", tags=["Reports"])
async def download_csv(filtered: bool = Query(False)) -> StreamingResponse:
    """Download the current dataset (or filtered subset) as CSV."""
    df, _ = _require_data()
    csv_bytes = generate_csv(df, filtered=filtered)
    import io
    return StreamingResponse(
        io.BytesIO(csv_bytes),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="cybervision_report.csv"'},
    )


# ---------------------------------------------------------------------------
# Reports – PDF
# ---------------------------------------------------------------------------
@app.post("/api/reports/pdf", tags=["Reports"])
async def generate_pdf_report(body: dict = None) -> StreamingResponse:
    """Generate a PDF report from the current analysis."""
    _, _ = _require_data()
    analysis = _state.get("analysis", {})
    if body is None:
        body = {}
    include_charts = body.get("include_charts", True)
    try:
        pdf_bytes = generate_pdf(analysis, include_charts=include_charts)
        import io
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": 'attachment; filename="cybervision_report.pdf"'},
        )
    except Exception as exc:
        logger.exception("PDF generation failed")
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------
@app.get("/api/filters", tags=["Analysis"])
async def get_filters() -> JSONResponse:
    """Return available filter values derived from the loaded dataset."""
    df, col_map = _require_data()
    try:
        filters: dict = {}

        label_col = col_map.get("label")
        if label_col and label_col in df.columns:
            filters["categories"] = sorted(df[label_col].dropna().unique().tolist())

        severity_col = col_map.get("severity")
        if severity_col and severity_col in df.columns:
            filters["severities"] = sorted(df[severity_col].dropna().unique().tolist())

        protocol_col = col_map.get("protocol")
        if protocol_col and protocol_col in df.columns:
            filters["protocols"] = sorted(df[protocol_col].dropna().unique().tolist())

        timestamp_col = col_map.get("timestamp")
        if timestamp_col and timestamp_col in df.columns:
            ts = pd.to_datetime(df[timestamp_col], errors="coerce").dropna()
            if not ts.empty:
                filters["date_range"] = {
                    "min": ts.min().isoformat(),
                    "max": ts.max().isoformat(),
                }

        return JSONResponse(content=filters)
    except Exception as exc:
        logger.exception("Failed to build filters")
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Re-analyse with filters
# ---------------------------------------------------------------------------
@app.post("/api/analyze", tags=["Analysis"])
async def analyze_with_filters(body: dict = None) -> JSONResponse:
    """
    Re-run analysis with optional filters applied.

    Body (optional JSON):
    ```json
    {
        "category": "DoS Hulk",
        "severity": "High",
        "protocol": "TCP",
        "date_from": "2023-01-01",
        "date_to": "2023-01-07"
    }
    ```
    """
    df, col_map = _require_data()
    filters = body or {}
    try:
        filtered_df = apply_filters(df, filters)
        analysis = analyze_dataset(filtered_df, col_map)
        info = _state.get("analysis", {}).get("dataset_info", {})
        analysis["dataset_info"]["filename"] = info.get("filename", "N/A")
        analysis["dataset_info"]["file_size"] = info.get("file_size", "N/A")
        analysis["filters_applied"] = filters
        return JSONResponse(content=analysis)
    except Exception as exc:
        logger.exception("Filtered analysis failed")
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
