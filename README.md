# 🛡️ PhishShield AI — Enterprise Threat Intelligence & Multi-Tier Phishing Protection

PhishShield AI is a cybersecurity detection system combining sub-millisecond heuristic threat models, Tier 2 XGBoost machine learning on lexical/URL features, and Tier 3 Google Gemini Contextual AI via the official `google-genai` SDK, backed by SQLite telemetry persistence, a Chrome Extension (Manifest V3), and an Executive SOC Operations Dashboard.

---

## 📁 Repository Architecture

```text
phishshield/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                  # FastAPI Application, DB lifespan & Telemetry API
│   │   ├── config.py                # Environment, paths, weights & settings
│   │   ├── database.py              # SQLAlchemy engine & SQLite session factory
│   │   ├── models.py                # ScanLog & ThreatReport ORM models
│   │   ├── schemas.py               # Pydantic Request/Response Models & Tier Breakdown
│   │   ├── train_ml.py              # Synthetic dataset generator & XGBoost trainer
│   │   ├── pipeline/
│   │   │   ├── __init__.py
│   │   │   ├── evaluator.py         # 3-Tier Multi-Engine Fusion Orchestrator
│   │   │   ├── heuristics.py        # Tier 1: Typosquatting, Entropy & Rules (35% weight)
│   │   │   ├── feature_extractor.py # 12 Lexical numerical feature extractor
│   │   │   ├── ml_model.py          # Tier 2: XGBoost model inference wrapper (45% weight)
│   │   │   └── ai_context.py        # Tier 3: Gemini Contextual AI (20% weight)
│   │   └── utils/
│   │       ├── __init__.py
│   │       └── domain_tools.py      # Entropy & Cyber Forensics Helpers
│   ├── data/
│   │   ├── model.json               # Compiled XGBoost model binary
│   │   └── phishshield.db           # SQLite database for scan logs & reports
│   ├── train_ml.py                  # Root CLI trainer script
│   ├── smoke_test.py                # End-to-end API & telemetry verification
│   ├── test_engine.py               # Automated unit test suite (8 tests)
│   ├── requirements.txt
│   ├── .env.example
│   └── .env
├── dashboard/
│   ├── index.html                   # Real-Time SOC Operations Center & Judge Sandbox
│   ├── app.js                       # Real-time polling, Radar animations & REST client
│   ├── style.css                    # Dark Slate Enterprise SOC Theme
│   └── assets/                      # Brand Logos, Shields & Favicons
└── extension/
    ├── manifest.json                # Manifest V3 Extension Config
    ├── background.js                # Service Worker (Context Menu & API Fetch)
    ├── content.js                   # In-page Warning Interception Banner
    ├── popup.html                   # Dark Slate Extension Popup UI
    ├── popup.js                     # Popup Interaction Controller
    ├── styles.css                   # Cybersecurity Design Tokens
    └── icons/                       # 16px, 48px, 128px Shield & Logo Icons
```

---

## ⚡ Three-Tier Multi-Engine Scoring Architecture

PhishShield AI fuses 3 distinct security engines into a weighted composite threat rating:

$$\text{Final Risk Score} = (0.35 \times \text{Tier 1 Heuristics}) + (0.45 \times \text{Tier 2 XGBoost ML}) + (0.20 \times \text{Tier 3 Gemini AI})$$

| Tier | Engine | Features / Focus | Latency | Weight |
| :--- | :--- | :--- | :--- | :--- |
| **Tier 1** | **Heuristic Forensics** | Typosquatting, Leetspeak, Shannon entropy, Raw IPs, Subdomain brand hijacking, Punycode/IDN, Top Verified Domains Whitelist | `< 3ms` | **35%** |
| **Tier 2** | **XGBoost ML** | 12 Lexical features (`url_length`, `dot_count`, `hyphen_count`, `is_ip_address`, `subdomain_count`, etc.) | `< 5ms` | **45%** |
| **Tier 3** | **Gemini AI Context** | Natural language reasoning, urgency manipulation, fear triggers, credential harvesting | `~ 600ms` | **20%** |

---

## 🚀 Quick Start Guide

### 1. Backend Server Setup

```bash
# Navigate to backend directory
cd backend

# Install dependencies
pip install -r requirements.txt

# (Optional) Retrain Tier 2 XGBoost model
python train_ml.py

# Start the FastAPI backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

- **Interactive API Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Health Endpoint**: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

---

### 2. Live Executive SOC Dashboard

To launch the real-time SOC dashboard:

```bash
# From the project root
python -m http.server 3000 --directory dashboard
```

Open **[http://127.0.0.1:3000](http://127.0.0.1:3000)** in your browser:
- **Top Metric Cards**: Live counter for Total URLs Audited, Active Threats Blocked, Engine Latency, and Community Reports.
- **Live Telemetry Stream**: Real-time auto-polling table of incoming scans with dedicated inspect modal.
- **Judge Testing Sandbox**: 1-click test link presets (🟢 Safe, 🔴 Typosquat, 🔴 Raw IP, 🟡 Subdomain Spoof, 🔴 DGA), with live animated 3-tier Risk Radar and AI reasoning card.
- **Community Threat Reporting**: Submit scam URLs directly to the SQLite intelligence database with 1-click shareable threat advisories.

---

### 3. Chrome Extension (Manifest V3)

1. Open Google Chrome and navigate to `chrome://extensions`.
2. Toggle **Developer mode** in the top right corner.
3. Click **Load unpacked**.
4. Select the `extension/` directory.

---

## 📡 API Endpoints

- `POST /api/v1/scan`: Multi-tier link audit returning score, level, verdict, factors, and 3-tier breakdown.
- `POST /api/v1/report`: Submit a community scam URL report.
- `GET /api/v1/analytics/stats`: Real-time aggregated statistics (Total scans, threats, avg latency, risk breakdown).
- `GET /api/v1/analytics/recent`: Retrieve the latest audit events from the SQLite database.
- `GET /api/v1/reports`: Fetch recent community threat reports.
- `GET /health`: Engine status, model readiness, and AI probe.

---

## 🧪 Automated Testing

```bash
# Run automated diagnostic test suite
cd backend
python test_engine.py

# Run live endpoint smoke test
python smoke_test.py
```
