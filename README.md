# CyberVision AI 🛡️
### Cybersecurity Data Analysis & Visualization Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688.svg)](https://fastapi.tiangolo.com/)
[![Chart.js](https://img.shields.io/badge/Chart.js-4.4+-FF6384.svg)](https://www.chartjs.org/)

**CyberVision AI** is an interactive, local-first cybersecurity analytics platform built to ingest network security logs, automatically detect available security attributes, compute statistical summaries, visualize threat trends, and generate structured analysis reports.

Designed as a premier college computer engineering project and production-grade security analytics prototype, CyberVision AI runs entirely locally without paid cloud APIs, external tracking, or complex SIEM dependencies.

---

## 📸 Dashboard Preview

```
+---------------------------------------------------------------------------------------+
|  CYBERVISION AI             [ Sample Dataset Loaded: 104 rows ]   [Upload CSV] [Load] |
+---------------------------------------------------------------------------------------+
| [Overview]       | TOTAL RECORDS   UNIQUE SOURCES   UNIQUE TARGETS   HIGH/CRIT EVENTS |
| [Explorer]       |     104               16               14                40        |
| [Threats]        +--------------------------------------------------------------------+
| [Traffic]        | THREAT CLASSIFICATION (Chart)       NETWORK PROTOCOLS (Chart)      |
| [Visualizations] | [DoS Hulk, PortScan, Brute Force]   [TCP 88%, UDP 12%]             |
| [Reports]        +--------------------------------------------------------------------+
| [About Project]  | DATA QUALITY AUDIT: 0 Missing Cells | 0 Duplicate Records          |
| [Settings]       | RECENT SECURITY FINDINGS & SUSPICIOUS PATTERN HEURISTICS           |
+---------------------------------------------------------------------------------------+
```

*(Screenshots can be added to `docs/screenshots/` once deployed)*

---

## 🎨 Visual Design & Modern Light SaaS Theme

Unlike traditional dark terminal hacker aesthetics, CyberVision AI features a modern, clean light SaaS interface:

| Element | Role | Hex Code | Visual Preview |
| :--- | :--- | :--- | :--- |
| **Main Background** | Dashboard Canvas | `#F7F8FC` | Soft neutral grey-white |
| **Card Background** | Elevated Surfaces | `#FFFFFF` | Crisp pure white |
| **Primary Indigo** | Primary Buttons & Active Links | `#635BFF` | Vivid Indigo |
| **Secondary Violet**| Gradient Accents | `#8B5CF6` | Soft Violet |
| **Mint Highlight** | Success & Validations | `#DDF8E8` / `#16A34A` | Refreshing Mint Green |
| **Pale Blue** | Info Panels & Metric Boxes | `#E8F1FF` / `#3B82F6` | Calming Sky Blue |
| **Lavender** | Secondary Tags & Badges | `#F0EAFE` / `#7C3AED` | Soft Lavender |
| **Warning Amber** | Elevated Threats & Warnings | `#F59E0B` | Warm Amber |
| **Critical Red** | High Severity Intrusions | `#DC2626` | Bold Crimson |
| **Navy Text** | High-Contrast Typography | `#20243A` | Deep Navy |

---

## 🌟 Key Features

1. **Flexible Column Recognition Engine**:
   - Dynamically recognizes variations of headers: `timestamp`, `source_ip`, `destination_ip`, `source_port`, `destination_port`, `protocol`, `bytes_transferred`, `packets`, `attack_type`, `severity`, `event_type`, `login_attempts`, `failed_login_attempts`.
   - Adapts to missing columns gracefully without crashing.
2. **Dashboard Overview (6 Core KPI Cards)**:
   - Total Records, Unique Source IPs, Unique Destination IPs, High-Severity Events, Missing Value Count, and Rule-Flagged Suspicious Records.
3. **Dataset Explorer**:
   - Live paginated data grid (15, 25, 50, 100 rows per page) with instant multi-column search, column header click-to-sort, and safe HTML escaping.
4. **Threat Analytics**:
   - Severity distribution (Critical, High, Medium, Low, Informational), attack classification frequency, and heuristic anomaly detections (port scanning probes, authentication failures, volumetric spikes).
5. **Network Traffic Analysis**:
   - Source IP frequency ranking, destination port reconnaissance (identifying common service ports: HTTP, HTTPS, SSH, DNS, RDP), protocol volume breakdown, and time-series event clustering.
6. **Data Visualization Gallery (8 Interactive Chart.js Charts)**:
   - Protocol Distribution Donut Chart
   - Attack Type Frequency Bar Chart
   - Security Event Trends Line Chart
   - Threat Severity Breakdown Doughnut Chart
   - Top Originating Source IPs Horizontal Bar Chart
   - Top Destination Ports Bar Chart
   - Security Event Types Bar Chart
   - Missing Values Audit Bar Chart
   - One-click PNG chart export feature.
7. **Report Generation & Export**:
   - Export analysis summaries in formatted CSV or structured JSON formats with complete audit metadata and methodological boundaries.
8. **Settings & Customization**:
   - Switchable light accent themes (Indigo, Lavender, Pale Blue, Mint) and chart animation controls stored in browser `localStorage`.

---

## ⚙️ Technology Stack

- **Frontend**: HTML5, CSS3, JavaScript (Vanilla ES6+), Font Awesome 6, Chart.js 4.4
- **Backend**: Python 3.10+, FastAPI, Uvicorn, Pydantic
- **Data Processing**: Pandas, NumPy, Python-Dateutil
- **Testing**: Pytest, HTTPX

---

## 📁 Project Directory Structure

```
CyberVision-AI/
│
├── backend/
│   ├── __init__.py           # Python package marker
│   ├── main.py               # FastAPI application & analysis pipeline
│   └── tests/
│       └── test_analysis.py  # Automated unit & integration tests
│
├── frontend/
│   ├── index.html            # Unified Single-Page Application (SPA)
│   ├── style.css             # Light theme SaaS styles & responsive queries
│   └── script.js             # SPA routing, Chart.js managers, table pagination
│
├── data/
│   ├── sample_cybersecurity.csv # Synthetic demonstration dataset
│   └── README.md             # Dataset schema & scenario documentation
│
├── .gitignore                # Git ignore configuration
├── README.md                 # Complete project documentation
├── requirements.txt          # Python dependency specifications
├── LICENSE                   # MIT open-source license
├── render.yaml               # Cloud deployment configuration
└── start.bat                 # Windows one-click local launcher
```

---

## 🚀 Local Installation & Execution (VS Code on Windows)

### Prerequisites
- Python 3.10 or higher installed. Verify with:
  ```powershell
  python --version
  ```

### Step 1: Clone or Navigate to the Workspace
```powershell
cd CyberVision-AI
```

### Step 2: Create a Python Virtual Environment
```powershell
python -m venv .venv
```

### Step 3: Activate the Virtual Environment
On Windows PowerShell:
```powershell
.\.venv\Scripts\Activate.ps1
```
*(If PowerShell execution policy restricts scripts, run: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`)*

On macOS/Linux:
```bash
source .venv/bin/activate
```

### Step 4: Install Dependencies
```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Step 5: Start the CyberVision AI Backend
```powershell
python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```
*Or simply double-click `start.bat` on Windows.*

### Step 6: Open the Application
- **Main Website**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive Swagger API Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Alternative ReDoc API Docs**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)
- **API Health Check**: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

---

## 🧪 Running Automated Tests

Run the full automated test suite using Pytest:

```powershell
python -m pytest backend/tests/test_analysis.py -v
```

All 10 test scenarios evaluate:
- Health check endpoints
- Column alias detection
- Severity normalization
- Sample dataset analysis
- Graceful handling of missing columns
- Custom CSV upload parsing
- JSON and CSV report generation
- Active dataset clearing and state reset

---

## 📊 Sample Dataset Instructions

A pre-packaged synthetic dataset is included in `data/sample_cybersecurity.csv`. It contains 104 illustrative records simulating:
- Normal HTTPS web browsing and DNS lookups
- HTTP DoS Hulk floods
- UDP DDoS amplification attacks
- Multi-port reconnaissance port scanning
- SSH authentication brute-force attempts
- Web SQL injection probes
- Botnet C2 beaconing

To test the application:
1. Click the **"Load Sample"** button in the top navigation bar or Overview banner.
2. The platform will automatically populate all 6 KPI cards, 8 interactive charts, the Dataset Explorer table, and the live reports view.
3. You can also click **"Download Sample CSV"** to save the file locally for external inspection.

---

## 📤 Uploading Custom Datasets

1. Click **"Upload CSV"** in the top navigation bar or drag and drop a file into the Overview upload container.
2. Maximum supported upload size is **50MB**.
3. Supported format is standard Comma-Separated Values (`.csv`).
4. The system validates file encoding (UTF-8, Latin-1, CP1252) and detects columns automatically.

---

## 🔒 Security Considerations

- **Server-Side Validation**: All files are validated for size (50MB cap) and CSV structure before parsing.
- **Client-Side HTML Escaping**: Dataset strings are sanitized via `escapeHtml()` prior to DOM insertion, preventing XSS vulnerabilities.
- **Local-First Privacy**: Uploaded records reside only in volatile server memory during the active session. No data is stored permanently or sent to external AI vendors.
- **Error Obfuscation**: Internal server stack traces are not leaked to API callers.

---

## ⚠️ Project Limitations & Ethical Disclaimers

- **Synthetic Nature**: The included sample data is 100% synthetically generated for academic demonstration and does not reflect actual real-world attacks.
- **Batch Processing**: CyberVision AI is an offline batch dataset analysis engine, not an inline firewall or live packet sniffer.
- **Rule-Based Heuristics**: Anomaly detection alerts are based on statistical thresholds and configurable rules, not certified digital forensics evidence.

---

## 🔮 Future Enhancements

- Ingestion of `.pcap` and `.pcapng` packet capture files via Scapy.
- Integration of evaluated Machine Learning models (Random Forest, XGBoost) trained on open benchmarks (e.g. CIC-IDS2017).
- Real-time syslog stream listener via WebSockets.
- Export to automated PDF executive briefs.

---

## 🚀 GitHub Upload Instructions

To upload this repository to GitHub under `CyberVision-AI`:

```powershell
# 1. Initialize git (if not already initialized)
git init

# 2. Add all files
git add .

# 3. Commit changes
git commit -m "feat: complete CyberVision AI platform implementation"

# 4. Set main branch
git branch -M main

# 5. Link your remote repository (replace with your GitHub URL)
git remote add origin https://github.com/YOUR_USERNAME/CyberVision-AI.git

# 6. Push to GitHub
git push -u origin main
```

---

## ☁️ Deployment Instructions (Render)

This repository includes a native `render.yaml` specification for zero-config deployment on [Render](https://render.com):

1. Push your repository to GitHub.
2. Log into the Render Dashboard and choose **New > Blueprint**.
3. Select your `CyberVision-AI` repository.
4. Render will automatically read `render.yaml`, configure Python 3.11, install `requirements.txt`, and start Uvicorn.
5. Your platform will be accessible publicly via `https://<your-app-name>.onrender.com`.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
