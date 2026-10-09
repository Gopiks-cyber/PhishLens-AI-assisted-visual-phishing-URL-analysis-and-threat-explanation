# PhishLens

AI-assisted visual phishing URL analysis and threat explanation.

## Overview

PhishLens is a lightweight, client-heavy web application that performs **static, heuristic analysis** of submitted URLs to identify phishing indicators. It provides an **explainable risk score**, an **interactive URL anatomy visualization**, and a **component-level Threat Map** that links detected indicators to specific URL components. No network requests are made to the analyzed URL; all analysis runs locally on the server using static pattern matching.

## Problem Statement

Phishing attacks often exploit URL structure—subdomain spoofing, lookalike domains, misleading paths, and URL shorteners—to trick users into visiting malicious sites. Security analysts and end-users need a tool that:

- Breaks down a URL into its structural components
- Explains *why* a component is suspicious with evidence
- Provides an explainable, capped risk score with per-indicator contributions
- Does not fetch or execute the target URL (safe for analyzing live threats)
- Works offline for the analysis engine (no external API dependencies)

## Objectives

- Provide a **dark-themed, accessible web UI** for manual URL submission and optional screenshot OCR
- Deliver **explainable risk scoring** (0–100) with per-indicator contribution bars
- Visualize **URL anatomy** as clickable, keyboard-accessible pills (protocol, subdomain, domain, TLD, path, query, fragment)
- Show a **Threat Map** panel that updates on component selection, linking API indicators and client-side structural anomalies to the selected component
- Surface **actionable recommendations** based on risk level and specific indicator types
- Offer a **REST API** (`/api/analyze`) for programmatic integration

## Features

| Feature | Description |
|---------|-------------|
| **Heuristic URL Risk Analysis** | 15+ static checks covering IP hosts, suspicious TLDs, brand impersonation, excessive subdomains, URL shorteners, credential embedding, hyphenated brands, random subdomains, sensitive paths, excessive parameters, encoded characters, and dangerous schemes |
| **Explainable Risk Scoring** | Score 0–100 with breakdown: raw total, cap (100), final score, capped flag, and per-indicator contributions (name, severity, points, plain-English explanation) |
| **Interactive URL Anatomy** | Color-coded pills for each URL component; click or use Enter/Space/Arrow keys to select; shows component type and value |
| **Threat Map** | Panel updates on component selection; shows matched API risk indicators (with evidence, explanation, points), client-side structural anomalies (with reason), and score contribution; falls back to "no specific indicator matched" state |
| **Suspicious Indicators & Evidence** | Each indicator includes name, detail, severity (high/medium/low), evidence string, points, and explanation |
| **Recommendations** | Risk-level-based guidance plus indicator-specific advice (e.g., expand shorteners, verify domains, report to IT) |
| **Screenshot OCR URL Extraction** | Optional image upload; uses Tesseract.js (CDN) to extract text, regex-finds URLs, auto-fills the input; distinguishes "no URL found" from OCR engine/recognition failures |
| **Flask API Endpoints** | `GET /` (frontend), `POST /api/analyze` (analysis), `GET /health` (health check) |
| **Responsive Dark Theme** | CSS custom properties, Inter font, cyan accent, glassmorphism cards, mobile-friendly layout |

## Technology Stack

| Layer | Technology |
|-------|------------|
| Backend | Python 3.10+, Flask 3.0 |
| Frontend | Vanilla ES6+ JavaScript, CSS custom properties, no build step |
| OCR | Tesseract.js 5.x (loaded from jsDelivr CDN on demand) |
| Testing | pytest 8.x (80 backend tests) |
| Fonts | Inter (Google Fonts), JetBrains Mono (monospace) |

## Project Structure

```
PhishLens/
├── app.py                 # Flask application (3 routes)
├── analyzer.py            # Core analysis logic (pure functions, no I/O)
├── requirements.txt       # Flask, pytest
├── README.md              # This file
├── templates/
│   ├── index.html         # Main page (form, results, anatomy, threat map)
│   └── result.html        # Standalone result page (API consumer reference)
├── static/
│   ├── app.js             # Main UI logic (form, results, anatomy, threat map)
│   ├── script.js          # Shared utilities (URL parsing, OCR, toasts)
│   ├── style.css          # Complete styling (dark theme, anatomy, threat map, responsive)
│   └── favicon.svg
├── tests/
│   ├── test_analyzer.py   # Unit tests for validation, indicators, scoring, breakdown
│   └── test_api.py        # Integration tests for /api/analyze and /health
└── .gitignore
```

## Setup & Installation (Windows PowerShell)

```powershell
# 1. Clone and enter the repository
git clone <repository-url>
cd PhishLens-AI-assisted-visual-phishing-URL-analysis-and-threat-explanation

# 2. Create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt
```

## Running the Application

```powershell
# Start the Flask development server (default: http://localhost:5000)
python app.py

# Or explicitly set host/port
python app.py
# Server runs on 0.0.0.0:5000 with debug=True
```

Open `http://localhost:5000` in a browser.

## Running Tests

```powershell
# Run full test suite (80 tests)
python -m pytest tests/ -v

# Run with coverage (if coverage installed)
python -m pytest tests/ --cov=analyzer --cov=app
```

Expected output: **80 passed** (validation, indicators, scoring, breakdown, API endpoints, health check).

## API Documentation

### `GET /`

Serves the PhishLens single-page frontend (`templates/index.html`).

### `POST /api/analyze`

Analyze a URL for phishing indicators.

**Request:**
```json
{
  "url": "http://secure-login.paypal.com.phishersite.xyz/account/verify?redirect=https://paypal.com"
}
```

**Headers:**
- `Content-Type: application/json`

**Success Response (200):**
```json
{
  "url": "http://secure-login.paypal.com.phishersite.xyz/account/verify?redirect=https://paypal.com",
  "risk_score": 87,
  "risk_level": "high",
  "indicators": [
    {
      "name": "Brand Impersonation",
      "detail": "Subdomain contains brand name 'paypal' but domain is not official",
      "severity": "high",
      "evidence": "subdomain contains 'paypal'",
      "points": 30,
      "explanation": "A known brand name appears in a subdomain while the registered domain is different..."
    },
    {
      "name": "Suspicious TLD",
      "detail": "Domain uses high-risk TLD: .xyz",
      "severity": "medium",
      "evidence": "tld=.xyz",
      "points": 15,
      "explanation": "The domain uses a top-level domain that is statistically over-represented in phishing campaigns..."
    }
  ],
  "recommendations": [
    "Do not visit this URL. It shows strong indicators of phishing.",
    "Report this URL to your IT security team or the legitimate organization being impersonated.",
    "Check for subtle misspellings or extra subdomains mimicking known brands."
  ],
  "score_breakdown": {
    "raw_total": 95,
    "cap": 100,
    "final_score": 87,
    "capped": false,
    "contributions": [
      { "name": "Brand Impersonation", "severity": "high", "points": 30, "explanation": "..." },
      { "name": "Suspicious TLD", "severity": "medium", "points": 15, "explanation": "..." }
    ]
  }
}
```

**Error Response (400):**
```json
{
  "url": "",
  "risk_score": 0,
  "risk_level": "error",
  "indicators": [],
  "recommendations": ["Request must be JSON with Content-Type: application/json"],
  "error": "Invalid content type"
}
```

### `GET /health`

Health check endpoint.

**Response (200):**
```json
{ "status": "ok" }
```

## Risk Levels

| Score Range | Level | Meaning |
|-------------|-------|---------|
| 0–14 | `minimal` | No significant phishing indicators detected |
| 15–39 | `low` | Some suspicious patterns; remain vigilant |
| 40–69 | `medium` | Multiple indicators; exercise caution, verify independently |
| 70–100 | `high` | Strong indicators of phishing; do not visit |

## Limitations

- **Heuristic, not definitive**: Scores and indicators are statistical heuristics. A high score does not prove a URL is malicious; a low score does not guarantee safety.
- **No network fetches**: The analyzer never makes HTTP requests to the submitted URL. It cannot detect server-side cloaking, redirects, or dynamic content.
- **Static analysis only**: No machine learning, no threat-intelligence feeds, no reputation lookups.
- **OCR quality dependent**: Screenshot URL extraction requires clear, high-contrast text; Tesseract.js loads from CDN (requires internet on first use).
- **TLD list is static**: The suspicious TLD list is a snapshot and may not reflect current abuse trends.
- **Brand list is curated**: Only a predefined set of brands is checked; new targets are not automatically detected.

## Security & Responsible Use

- **Safe by design**: No outbound requests to user-supplied URLs. The backend only parses the URL string.
- **No secrets in repo**: No API keys, tokens, or `.env` files committed. The only external dependency is the Tesseract.js CDN.
- **Input validation**: All endpoints validate JSON structure and URL format; malformed input returns structured errors.
- **Educational purpose**: PhishLens is a research/education tool. It is not a production-grade security gateway.
- **Report responsibly**: If you discover a phishing URL, report it to the legitimate organization's security team and/or a relevant CERT/ISAC.

## License

MIT License — see `LICENSE` if present, otherwise standard MIT terms apply.