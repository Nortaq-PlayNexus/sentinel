"""Incident analyzer — AI-powered root cause analysis."""

from __future__ import annotations
import json
import requests
from datetime import datetime, timezone
from typing import Any


ANALYSIS_PROMPT = """You are an SRE incident commander. Analyze the following alert data and provide:

1. Root cause analysis
2. Impact assessment (severity, affected services, estimated blast radius)
3. Recommended remediation steps (specific, actionable, ordered by priority)
4. Prevention recommendations

Respond in JSON format:
{
  "incident_id": "string",
  "title": "string",
  "severity": "P1|P2|P3|P4",
  "root_cause": "string",
  "impact": {
    "severity": "critical|high|medium|low",
    "affected_services": ["string"],
    "blast_radius": "string",
    "estimated_downtime": "string"
  },
  "timeline": [
    {"time": "string", "event": "string"}
  ],
  "remediation_steps": [
    {"order": 1, "action": "string", "command": "string", "risk": "low|medium|high"}
  ],
  "prevention": ["string"]
}"""


class IncidentAnalyzer:
    def __init__(self, config: dict, display: Any = None):
        self.config = config
        self.display = display
        self.llm_config = config.get("llm", {})
        self.api_key = self.llm_config.get("api_key", "")
        self.model = self.llm_config.get("model", "gpt-4o")
        self.base_url = self.llm_config.get("base_url", "https://api.openai.com/v1")

    def analyze(self, alert_data: dict) -> dict:
        if self.display:
            self.display.print_step("Analyzing incident data...")

        try:
            result = self._llm_analyze(alert_data)
        except Exception as e:
            if self.display:
                self.display.print_step(f"LLM unavailable, using rule-based analysis: {e}")
            result = self._rule_based_analyze(alert_data)

        result.setdefault("incident_id", f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}")
        result.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        result.setdefault("raw_alerts", alert_data)

        self._store_incident(result)
        return result

    def _llm_analyze(self, alert_data: dict) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": ANALYSIS_PROMPT},
                {"role": "user", "content": json.dumps(alert_data, indent=2)},
            ],
            "temperature": 0.2,
            "max_tokens": 4096,
        }

        resp = requests.post(
            f"{self.base_url}/chat/completions",
            headers=headers, json=payload, timeout=120,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]

        start = content.find("{")
        end = content.rfind("}") + 1
        if start != -1 and end > start:
            return json.loads(content[start:end])
        return {"title": "Unclassified Incident", "severity": "P3", "root_cause": content}

    def _rule_based_analyze(self, alert_data: dict) -> dict:
        alerts = alert_data.get("alerts", [alert_data])
        severity = self._infer_severity(alerts)
        services = set()
        for alert in alerts:
            svc = alert.get("service") or alert.get("labels", {}).get("service", "unknown")
            services.add(svc)

        return {
            "title": alert_data.get("summary", alert_data.get("title", "Production Incident")),
            "severity": severity,
            "root_cause": "Automated analysis — LLM unavailable. Manual review required.",
            "impact": {
                "severity": severity_to_level(severity),
                "affected_services": list(services),
                "blast_radius": f"{len(services)} service(s) affected",
                "estimated_downtime": "Unknown",
            },
            "timeline": [
                {"time": datetime.now(timezone.utc).isoformat(), "event": "Alert received by Sentinel"}
            ],
            "remediation_steps": [
                {"order": 1, "action": "Investigate alert details manually", "command": "", "risk": "low"},
                {"order": 2, "action": "Check service health dashboards", "command": "", "risk": "low"},
                {"order": 3, "action": "Consider rollback if recent deployment", "command": "git revert HEAD --no-edit", "risk": "medium"},
            ],
            "prevention": ["Enable LLM integration for AI-powered diagnosis"],
        }

    def _infer_severity(self, alerts: list[dict]) -> str:
        for alert in alerts:
            sev = alert.get("severity", "").upper()
            if sev in ("CRITICAL", "FATAL"):
                return "P1"
            if sev == "WARNING":
                return "P2"
        return "P3"

    def _store_incident(self, incident: dict):
        import os
        incidents_dir = Path("data/incidents") if os.path.exists("data") else Path("sentinel-data/incidents")
        incidents_dir.mkdir(parents=True, exist_ok=True)
        iid = incident.get("incident_id", "unknown")
        with open(incidents_dir / f"{iid}.json", "w") as f:
            json.dump(incident, f, indent=2, default=str)


def severity_to_level(sev: str) -> str:
    mapping = {"P1": "critical", "P2": "high", "P3": "medium", "P4": "low"}
    return mapping.get(sev.upper(), "medium")
