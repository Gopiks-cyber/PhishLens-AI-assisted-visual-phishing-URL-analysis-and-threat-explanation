# PhishLens Documentation Assets

This directory contains the image assets referenced in the root `README.md`.

## Required Images

### `architecture.png`
- **Description:** PhishLens system architecture diagram
- **Content:** A diagram showing the client-server architecture with:
  - Flask backend exposing REST endpoints (`/api/analyze`, `/api/investigations`, `/api/investigations/<id>/report.pdf`, `/health`)
  - Single-page frontend served from `templates/index.html`
  - Core analyzer (`analyzer.py`) with pure functions (no I/O, no network calls)
  - SQLite persistence layer (`investigations.py`) with parameterized queries
  - PDF report generator (`report.py`) using ReportLab
  - Client-side OCR via Tesseract.js loaded from CDN
  - Static assets: `static/app.js`, `static/style.css`, `static/script.js`

### `output.png`
- **Description:** Real screenshot of the running PhishLens application
- **Content:** Should demonstrate the cyber-intelligence themed dashboard including:
  - URL Scanner panel with URL input and optional screenshot upload
  - Overview panel with risk ring, analyzed URL, interactive URL anatomy pills (with clickable subdomain segments), suspicious components, HTTPS note, and risk indicators
  - Threat Map panel showing matched indicators, structural anomalies, and score contributions for selected component
  - Risk Breakdown panel with raw total, cap, final score, and per-indicator contribution bars
  - Recommendations panel with risk-level-based and indicator-specific guidance
  - Investigations tab listing saved analyses with risk level, score, timestamp, and actions to open stored result or download PDF evidence report

## Notes

- **Do not fabricate placeholder images.** The actual image files must be added by the project maintainers.
- Both image files should be placed directly inside this `docs/` directory.
- The root `README.md` references these exact paths:
  - `![Architecture Diagram](docs/architecture.png)`
  - `![Output Screenshot](docs/output.png)`