# CyberVision AI 🛡️
### Interactive Cybersecurity Analytics & Machine Learning Threat Intelligence Platform

**CyberVision AI** is a web-based cybersecurity intelligence platform designed to ingest network telemetry datasets, analyze security events, detect potential anomalies, and present actionable insights through interactive dashboards and downloadable executive reports.

---

## 🎨 Recommended Visual Theme & Color Palette

The interface adheres to an ultra-modern light SaaS design:

| Element | Color Role | Hex Code |
| :--- | :--- | :--- |
| **Main Background** | Very light blue | `#F4F8FF` |
| **Cards & Surfaces** | Pure White | `#FFFFFF` |
| **Primary Actions** | Bright Blue | `#4776E6` |
| **Secondary Accent** | Violet Purple | `#8B5CF6` |
| **Highlight & Links** | Cyan | `#22C7D9` |
| **Success Indicators**| Mint Green | `#34D399` |
| **Warning Indicators**| Amber Orange | `#F59E0B` |
| **High Severity** | Coral Red | `#F87171` |
| **Main Typography** | Navy Blue | `#23345D` |

---

## 🌐 7 Complete Website Pages

1. **Home Page (`index.html`)**: Introduces the platform, features an animated network topology illustration, metrics, use case cards, and interactive dashboard preview.
2. **Analytics Dashboard (`dashboard.html`)**: The primary command center. Displays 5 high-level KPI cards (Total Records, Normal Records, Attack Records, Potential Anomalies, Attack Categories), interactive Chart.js charts (Category distribution, Normal vs. Attack doughnut, 24h event trends, Severity breakdown, Protocol distribution), and an interactive data table with live filters.
3. **Dataset Upload (`upload.html`)**: Drag-and-drop CSV uploader with real-time file validation, schema mapping, column preview badges, and instant built-in sample dataset loaders.
4. **Attack Analysis (`analysis.html`)**: Deep dive into attack categories, timeline distributions, severity comparisons, protocol shares, top malicious source IP addresses, and side-by-side category comparisons.
5. **Anomaly Detection (`anomaly.html`)**: Identifies potential deviations and outliers using **Rule-Based Heuristics**, **Statistical Z-Scores**, and **Machine Learning Isolation Forest**. Includes confidence scoring and anomalous record exploration.
6. **Reports & Export (`reports.html`)**: Download filtered subsets as CSV, raw machine-readable JSON, or compiled executive PDF summary briefs.
7. **About Project (`about.html`)**: Complete architectural documentation, problem statement, research methodologies, benchmark datasets (UNSW-NB15, CIC-IDS2017), limitations, and future scope.

---

## ⚙️ Technology Stack

- **Frontend**: HTML5, CSS3 (Custom Responsive Variables), Vanilla JavaScript (ES6+), Font Awesome 6
- **Visualization**: Chart.js 4.4.x
- **Backend API**: Python 3.10+, FastAPI, Uvicorn
- **Data Engineering**: Pandas, NumPy
- **Machine Learning**: Scikit-learn (Isolation Forest)
- **Reporting**: ReportLab (PDF Generation)

---

## 🚀 Quick Start Guide

### 1. Launching the Frontend
No build step or Node.js environment is required. Simply open `frontend/index.html` in any web browser.

### 2. Starting the Python FastAPI Backend
Open a terminal in `CyberVision-AI/backend`:

```powershell
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the server
uvicorn main:app --reload --port 8000
```
Or simply double-click `backend/start.bat` on Windows.

- **API Base URL**: `http://localhost:8000`
- **Swagger Documentation**: `http://localhost:8000/api/docs`
- **ReDoc Documentation**: `http://localhost:8000/api/redoc`

---

## 🧪 Running Automated Tests
```powershell
cd backend
pytest tests/test_analysis.py -v
```

---

## 📁 Repository Structure

```
CyberVision-AI/
├── frontend/
│   ├── index.html            # Landing page
│   ├── dashboard.html        # Analytics dashboard
│   ├── upload.html           # Dataset uploader
│   ├── analysis.html         # Attack category analysis
│   ├── anomaly.html          # Anomaly detection (ML/Rules)
│   ├── reports.html          # Export & PDF reports
│   ├── about.html            # Documentation & architecture
│   ├── css/
│   │   └── style.css         # Complete SaaS stylesheet
│   └── js/
│       ├── main.js           # Core utilities & API wrapper
│       ├── dashboard.js      # Dashboard reactive state
│       ├── upload.js         # Uploader & file parsing
│       └── analysis.js       # Attack charts & filters
├── backend/
│   ├── main.py               # FastAPI entry point & routes
│   ├── requirements.txt      # Python dependencies
│   ├── start.bat             # One-click Windows runner
│   ├── services/
│   │   ├── data_loader.py    # CSV ingestion & column mapper
│   │   ├── data_cleaner.py   # Missing value & label normalization
│   │   ├── analysis_service.py # Metrics & temporal aggregation
│   │   ├── anomaly_service.py  # Isolation Forest & Z-scores
│   │   └── report_service.py   # PDF & CSV generation
│   └── tests/
│       └── test_analysis.py  # Unit & integration tests
├── data/
│   └── sample_dataset.csv    # 500+ records benchmark network telemetry
├── README.md
└── .gitignore
```

---

## ⚖️ Academic & Operational Disclaimer
*CyberVision AI is an offline analytics platform for forensic analysis, benchmarking, and security education. It evaluates uploaded telemetry datasets and does not directly intercept live production network packets.*
