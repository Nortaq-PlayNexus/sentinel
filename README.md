<div align="center">

# Sentinel

**AI Incident Commander — detect, diagnose, and remediate production incidents with AI.**

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-%3E%3D3.11-3776AB?logo=python&logoColor=white)](https://python.org)

</div>

**Sentinel** is an AI-powered incident response tool that detects alerts, performs root cause analysis, generates remediation steps, and can optionally execute fixes automatically.

No more war rooms at 3 AM. Sentinel diagnoses the problem and hands you the fix.

---

\n---\n\n## Screenshots\n\n| Preview | Description |\n|---------|-------------|\n| ![screenshot](docs/screenshots/screenshot.png) | Main interface |\n| ![screenshot](docs/screenshots/demo.gif) | Demo |\n\n*Screenshots coming soon — placeholders auto-generated. Replace docs/screenshots/ with real captures.*\n\n## Features

### AI root cause analysis
- Ingests alert data from any source (Prometheus, Grafana, Datadog, webhooks, files)
- Uses LLM to analyze logs, metrics, and traces
- Produces structured incident reports with severity, impact, and timeline

### Automated remediation
- Generates ordered remediation steps with risk levels
- Dry-run mode to preview actions before executing
- Safe low-risk commands execute automatically
- High-risk commands require manual approval

### Alert watching
- Polls multiple alert sources on a configurable interval
- Deduplicates alerts automatically
- Supports Prometheus, webhook, and file-based sources

---

## Quick start

```bash
# Install
pip install -e .

# Set your API key
export OPENAI_API_KEY=sk-...

# Diagnose from a file
sentinel diagnose alerts.json

# Diagnose from inline JSON
sentinel diagnose '{"alerts": [{"severity": "critical", "service": "api-gateway", "message": "503 spike"}]}'

# Dry-run remediation
sentinel remediate INC-20260809 --dry-run

# Watch for alerts
sentinel watch --config config/sentinel.json
```

---

## Alert sources

Configure in `config/sentinel.json`:

```json
{
  "alert_sources": [
    {"type": "prometheus", "url": "http://localhost:9090", "query": "ALERTS{alertstate=\"firing\"}"},
    {"type": "webhook", "url": "http://localhost:9090/api/v1/alerts"},
    {"type": "file", "path": "data/alerts.json"}
  ]
}
```

---

## How it works

```
Alert Sources (Prometheus / Webhooks / Files)
              │
              ▼
        ┌───────────┐
        │  Sentinel  │
        ├───────────┤
        │ Analyzer   │ ◄── AI root cause analysis
        │ Engine     │ ◄── Remediation generation
        │ Watcher    │ ◄── Multi-source polling
        └─────┬─────┘
              │
              ├──► Incident report (severity, impact, timeline)
              ├──► Remediation steps (ordered, risk-assessed)
              └──► Auto-remediation (optional, with dry-run)
```

---

## Configuration

```json
{
  "llm": {
    "model": "gpt-4o",
    "base_url": "https://api.openai.com/v1",
    "api_key": null
  },
  "remediation": {
    "auto_remediate": false,
    "require_approval_for": ["high"]
  }
}
```

Set `OPENAI_API_KEY` or `SENTINEL_API_KEY` environment variable.

---

## License

[MIT](LICENSE) — PlayNexus
