"""Incident analyzer - AI-powered root cause analysis."""

from __future__ import annotations
import json
import re
import requests
from datetime import datetime, timezone, timedelta
from pathlib import Path
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

SERVICE_DEPENDENCIES = {
    "api-gateway": ["auth-service", "user-service", "payment-service"],
    "auth-service": ["user-service", "redis"],
    "user-service": ["postgres", "redis"],
    "payment-service": ["postgres", "stripe-api"],
    "order-service": ["postgres", "redis", "payment-service"],
    "notification-service": ["smtp", "sms-gateway"],
    "web-frontend": ["api-gateway"],
    "worker": ["redis", "postgres"],
}

ESCALATION_THRESHOLDS = {
    "P1": {"immediate": True, "notify": ["oncall", "team-lead", "manager"]},
    "P2": {"immediate": True, "notify": ["oncall", "team-lead"]},
    "P3": {"immediate": False, "notify": ["oncall"]},
    "P4": {"immediate": False, "notify": ["oncall"]},
}


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

        root_cause = self._detect_root_cause(alerts)
        remediation = self._suggest_remediation(root_cause, list(services))

        return {
            "title": alert_data.get("summary", alert_data.get("title", "Production Incident")),
            "severity": severity,
            "root_cause": root_cause,
            "impact": {
                "severity": severity_to_level(severity),
                "affected_services": list(services),
                "blast_radius": f"{len(services)} service(s) affected",
                "estimated_downtime": "Unknown",
            },
            "timeline": self.build_timeline(alert_data),
            "remediation_steps": remediation,
            "prevention": ["Enable LLM integration for AI-powered diagnosis"],
            "correlations": self.correlate_alerts(alerts),
            "escalation": self.suggest_escalation(
                {"severity": severity, "services": list(services), "alerts": alerts}
            ),
        }

    def _detect_root_cause(self, alerts: list[dict]) -> str:
        for alert in alerts:
            msg = json.dumps(alert).lower()
            if "oom" in msg or "out of memory" in msg or "oomkill" in msg:
                return "Out of Memory (OOM) - process killed by kernel OOM killer. Check memory limits and usage."
            if "disk full" in msg or "no space left" in msg or "disk usage" in msg:
                return "Disk Full - filesystem exhausted. Check for log growth, temp files, or data accumulation."
            if "connection pool" in msg or "pool exhausted" in msg or "too many connections" in msg:
                return "Connection Pool Exhausted - all connections in use. Check for connection leaks or increase pool size."
            if "cpu" in msg and ("high" in msg or "95%" in msg or "100%" in msg):
                return "High CPU Usage - process consuming excessive CPU. Check for infinite loops or hot paths."
            if "503" in msg or "502" in msg or "service unavailable" in msg:
                return "Service Unavailable - upstream server returning 5xx errors. Check service health and dependencies."
            if "timeout" in msg:
                return "Timeout - request exceeded deadline. Check downstream services and network latency."
            if "deploy" in msg or "release" in msg or "rollout" in msg:
                return "Deployment-Related - issue correlates with recent deployment. Consider rollback."
            if "latency" in msg or "p99" in msg or "p95" in msg:
                return "High Latency - response times degraded. Check for resource contention or slow queries."
            if "queue" in msg and ("full" in msg or "backlog" in msg or "lag" in msg):
                return "Message Queue Backlog - consumer falling behind. Scale consumers or check processing errors."
            if "certificate" in msg or "tls" in msg or "ssl" in msg:
                return "TLS Certificate Issue - certificate may be expired or invalid. Renew certificate."
            if "dns" in msg or "resolution" in msg:
                return "DNS Resolution Failure - unable to resolve hostname. Check DNS server and records."
            if "killed" in msg or "crash" in msg or "panic" in msg:
                return "Process Crash - process terminated unexpectedly. Check logs for crash reason."
            if "rate limit" in msg or "throttl" in msg:
                return "Rate Limiting - requests throttled. Reduce request rate or increase limits."
            if "auth" in msg or "unauthorized" in msg or "forbidden" in msg:
                return "Authentication/Authorization Failure - credentials or permissions issue. Check tokens and IAM."
        return "Automated analysis - LLM unavailable. Manual review required."

    def _suggest_remediation(self, root_cause: str, services: list[str]) -> list[dict]:
        steps = []
        if "OOM" in root_cause or "memory" in root_cause.lower():
            steps = [
                {"order": 1, "action": "Check current memory usage", "command": "free -h && ps aux --sort=-%mem | head -20", "risk": "low"},
                {"order": 2, "action": "Increase memory limits if needed", "command": "", "risk": "medium"},
                {"order": 3, "action": "Restart affected service", "command": f"systemctl restart {services[0]}" if services else "", "risk": "medium"},
            ]
        elif "disk" in root_cause.lower():
            steps = [
                {"order": 1, "action": "Check disk usage", "command": "df -h", "risk": "low"},
                {"order": 2, "action": "Find large files", "command": "du -sh /* | sort -rh | head -20", "risk": "low"},
                {"order": 3, "action": "Clean old logs/temp files", "command": "find /var/log -name '*.log' -mtime +7 -delete", "risk": "medium"},
            ]
        elif "connection pool" in root_cause.lower():
            steps = [
                {"order": 1, "action": "Check active connections", "command": "ss -tuln | grep :5432", "risk": "low"},
                {"order": 2, "action": "Increase pool size in config", "command": "", "risk": "medium"},
                {"order": 3, "action": "Restart service to reset pool", "command": f"systemctl restart {services[0]}" if services else "", "risk": "medium"},
            ]
        elif "deploy" in root_cause.lower():
            steps = [
                {"order": 1, "action": "Identify last deployment", "command": "git log --oneline -5", "risk": "low"},
                {"order": 2, "action": "Rollback deployment", "command": "git revert HEAD --no-edit", "risk": "high"},
                {"order": 3, "action": "Verify rollback health", "command": "", "risk": "low"},
            ]
        elif "timeout" in root_cause.lower() or "latency" in root_cause.lower():
            steps = [
                {"order": 1, "action": "Check service metrics", "command": "", "risk": "low"},
                {"order": 2, "action": "Check downstream services", "command": "", "risk": "low"},
                {"order": 3, "action": "Scale up instances if needed", "command": "", "risk": "medium"},
            ]
        elif "503" in root_cause or "502" in root_cause or "unavailable" in root_cause.lower():
            steps = [
                {"order": 1, "action": "Check service status", "command": f"systemctl status {services[0]}" if services else "docker ps", "risk": "low"},
                {"order": 2, "action": "Check health endpoints", "command": "", "risk": "low"},
                {"order": 3, "action": "Restart service", "command": f"systemctl restart {services[0]}" if services else "", "risk": "medium"},
            ]
        else:
            steps = [
                {"order": 1, "action": "Investigate alert details manually", "command": "", "risk": "low"},
                {"order": 2, "action": "Check service health dashboards", "command": "", "risk": "low"},
                {"order": 3, "action": "Consider rollback if recent deployment", "command": "git revert HEAD --no-edit", "risk": "medium"},
            ]
        return steps

    def _infer_severity(self, alerts: list[dict]) -> str:
        for alert in alerts:
            sev = alert.get("severity", "").upper()
            if sev in ("CRITICAL", "FATAL"):
                return "P1"
            if sev == "WARNING":
                return "P2"
        return "P3"

    def correlate_alerts(self, alerts: list[dict]) -> dict:
        groups = {"by_service": {}, "by_time_window": {}, "by_dependency": {}}
        time_window_minutes = 5

        for alert in alerts:
            svc = alert.get("service") or alert.get("labels", {}).get("service", "unknown")
            groups["by_service"].setdefault(svc, []).append(alert)

            ts = alert.get("timestamp", alert.get("time", ""))
            if ts:
                try:
                    if isinstance(ts, str):
                        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    else:
                        dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
                    window_key = dt.strftime("%Y-%m-%dT%H:%M") + f"_{dt.minute // time_window_minutes * time_window_minutes:02d}"
                    groups["by_time_window"].setdefault(window_key, []).append(alert)
                except (ValueError, TypeError, OSError):
                    pass

        for alert in alerts:
            svc = alert.get("service") or alert.get("labels", {}).get("service", "unknown")
            deps = SERVICE_DEPENDENCIES.get(svc, [])
            for dep in deps:
                for other in alerts:
                    other_svc = other.get("service") or other.get("labels", {}).get("service", "")
                    if other_svc == dep:
                        groups["by_dependency"].setdefault(f"{svc}->{dep}", []).append(alert)

        return groups

    def build_timeline(self, incident: dict) -> list[dict]:
        timeline = []
        alerts = incident.get("alerts", [incident]) if isinstance(incident, dict) else []

        for alert in alerts:
            ts = alert.get("timestamp", alert.get("time", datetime.now(timezone.utc).isoformat()))
            summary = alert.get("summary", alert.get("description", alert.get("message", "Alert received")))
            svc = alert.get("service") or alert.get("labels", {}).get("service", "")
            entry = {"time": str(ts), "event": summary}
            if svc:
                entry["event"] = f"[{svc}] {summary}"
            timeline.append(entry)

        if not timeline:
            timeline.append({
                "time": datetime.now(timezone.utc).isoformat(),
                "event": "Incident created",
            })

        timeline.sort(key=lambda x: x["time"])
        return timeline

    def suggest_escalation(self, incident: dict) -> dict:
        severity = incident.get("severity", "P3")
        services = incident.get("services", [])
        alerts = incident.get("alerts", [])
        duration_minutes = 0

        if alerts:
            timestamps = []
            for alert in alerts:
                ts = alert.get("timestamp", alert.get("time"))
                if ts:
                    try:
                        if isinstance(ts, str):
                            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                        else:
                            dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
                        timestamps.append(dt)
                    except (ValueError, TypeError, OSError):
                        pass
            if len(timestamps) >= 2:
                duration_minutes = (max(timestamps) - min(timestamps)).total_seconds() / 60

        thresholds = ESCALATION_THRESHOLDS.get(severity, ESCALATION_THRESHOLDS["P3"])
        escalate_now = thresholds["immediate"] or duration_minutes > 30
        notify_list = list(thresholds["notify"])

        if len(services) > 3 and "manager" not in notify_list:
            notify_list.append("manager")
        if duration_minutes > 60 and "vp-engineering" not in notify_list:
            notify_list.append("vp-engineering")

        return {
            "escalate_now": escalate_now,
            "severity": severity,
            "duration_minutes": round(duration_minutes, 1),
            "notify": notify_list,
            "channel": "#incident-active" if severity in ("P1", "P2") else "#support",
        }

    def _store_incident(self, incident: dict):
        import os
        from pathlib import Path
        incidents_dir = Path("data/incidents") if os.path.exists("data") else Path("sentinel-data/incidents")
        incidents_dir.mkdir(parents=True, exist_ok=True)
        iid = incident.get("incident_id", "unknown")
        with open(incidents_dir / f"{iid}.json", "w") as f:
            json.dump(incident, f, indent=2, default=str)


def severity_to_level(sev: str) -> str:
    mapping = {"P1": "critical", "P2": "high", "P3": "medium", "P4": "low"}
    return mapping.get(sev.upper(), "medium")
