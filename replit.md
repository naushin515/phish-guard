# PhishGuard — Phishing URL Detection System

A cybersecurity portfolio project that analyzes URLs for phishing indicators, scores them 0–100, and classifies them as Safe / Suspicious / Phishing.

## Run & Operate

- `cd phishing-detector && python3 app.py` — run the Flask app (port 8000)
- Workflow: **"Phishing Detector"** — auto-starts the Flask server
- Required Python packages: `flask`, `werkzeug` (installed via uv into `.pythonlibs`)

## Stack

- Python 3.11 + Flask 3.x
- SQLite (via `sqlite3` stdlib) — stored at `phishing-detector/instance/phishing.db`
- Bootstrap 5 + Bootstrap Icons (CDN)
- pnpm workspaces (Node.js infra for the API server co-tenant)

## Where things live

```
phishing-detector/
├── app.py          — Flask routes & app factory
├── analyzer.py     — URL phishing analysis engine (10 indicators)
├── database.py     — SQLite CRUD helpers
├── requirements.txt
├── instance/       — SQLite database file (git-ignored)
├── templates/      — Jinja2 HTML templates (base, index, result, history, awareness, 404, 500)
└── static/
    ├── css/style.css   — Cybersecurity dark theme
    └── js/main.js      — Form validation, animated bars, table search
```

## Architecture decisions

- **Pure stdlib SQLite** — no ORM needed for a portfolio project; keeps dependencies minimal.
- **Client-side URL normalization** — analyzer prefixes `http://` if no scheme is given, so bare domains work.
- **Trusted-domain override** — known-good domains (Google, GitHub, etc.) are capped at "Suspicious" even if heuristics fire, avoiding obvious false positives.
- **10 independent indicator checks** — each returns a weight 0–N; scores are summed and clamped to 100. Classification thresholds: ≥60 = Phishing, ≥30 = Suspicious, else Safe.
- **Workflow as webview** — Flask app is registered as a Replit workflow on port 8000, not as a pnpm artifact.

## Product

Users paste any URL into the home page, click Analyze, and immediately see:
- A 0–100 risk score with animated progress ring
- Safe / Suspicious / Phishing classification
- Per-indicator breakdown grid
- Specific reasons triggered and actionable recommendations
- Full scan history stored in SQLite, with search and status filters
- Cybersecurity awareness education page

## User preferences

_Populate as you build — explicit user instructions worth remembering across sessions._

## Gotchas

- The Flask app lives in `phishing-detector/` — it is NOT a pnpm workspace package.
- Python packages are managed via `uv` into `.pythonlibs` — do not use `pip install` directly.
- The Node.js api-server runs concurrently on port 5000; Flask is on port 8000.
- Flask `PORT` env var is read on startup — changing the workflow port requires updating `app.py` default too.

## Pointers

- See the `pnpm-workspace` skill for Node.js workspace structure
- Python package management uses `uv` (Replit's default for Python 3.11+)
