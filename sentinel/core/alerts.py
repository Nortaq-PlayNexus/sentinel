"""Alert manager - watches for alerts from various sources."""

from __future__ import annotations
import json
import time
import hashlib
import requests
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinel.core.analyzer import IncidentAnalyzer

SEVERITY_MAP = {
    "critical": "P1",
    "error": "P1",
    "fatal": "P1",
    "warning": "P2",
    "warn": "P2",
    "info": "P3",
    "debug": "P4",
    "P1": "P1",
    "P2": "P2",
    "P3": "P3",
    "P4": "P4",
}


def enrich_alert(alert: dict) -> dict:
    if "timestamp" not in alert and "time" not in alert:
        alert["timestamp"] = datetime.now(timezone.utc).isoformat()
    raw_sev = alert.get("severity", alert.get("level", "")).lower()
    if raw_sev:
        alert["normalized_severity"] = SEVERITY_MAP.get(raw_sev, "P3")
    return alert


class AlertManager:
    def __init__(self, config: dict, display: Any = None):
        self.config = config
        self.display = display
        self.analyzer = IncidentAnalyzer(config, display)
        self.sources = config.get("alert_sources", [])
        self._seen_hashes: set[str] = set()

    def watch(self, interval: int = 30):
        if self.display:
            self.display.print_step(f"Watching for alerts (interval: {interval}s)...")

        if not self.sources:
            if self.display:
                self.display.print_step(
                    "No alert sources configured. Add sources to config/sentinel.json"
                )
                self.display.print_step("Example config:")
                self.display.print_step(
                    json.dumps(
                        {
                            "alert_sources": [
                                {
                                    "type": "webhook",
                                    "url": "http://localhost:9090/api/v1/alerts",
                                },
                                {"type": "file", "path": "data/alerts.json"},
                                {"type": "datadog", "api_key": "xxx", "app_key": "xxx"},
                                {"type": "pagerduty", "routing_key": "xxx"},
                                {
                                    "type": "slack_webhook",
                                    "webhook_url": "https://hooks.slack.com/services/...",
                                },
                                {
                                    "type": "healthcheck",
                                    "endpoints": [
                                        {
                                            "url": "http://localhost:8080/health",
                                            "service": "api",
                                        }
                                    ],
                                },
                            ]
                        },
                        indent=2,
                    )
                )
            return

        while True:
            for source in self.sources:
                alerts = self._fetch_alerts(source)
                for alert in alerts:
                    alert = enrich_alert(alert)
                    if self._is_new(alert):
                        if self.display:
                            self.display.print_step(
                                f"New alert from {source.get('type', 'unknown')}"
                            )
                        self.analyzer.analyze(alert)
            time.sleep(interval)

    def _fetch_alerts(self, source: dict) -> list[dict]:
        stype = source.get("type", "")
        try:
            if stype == "webhook":
                return self._fetch_webhook(source)
            elif stype == "file":
                return self._fetch_file(source)
            elif stype == "prometheus":
                return self._fetch_prometheus(source)
            elif stype == "datadog":
                return self._fetch_datadog(source)
            elif stype == "pagerduty":
                return self._fetch_pagerduty(source)
            elif stype == "slack_webhook":
                return self._fetch_slack_webhook(source)
            elif stype == "healthcheck":
                return self._fetch_healthcheck(source)
        except Exception as e:
            if self.display:
                self.display.print_step(f"Error fetching from {stype}: {e}")
        return []

    def _fetch_webhook(self, source: dict) -> list[dict]:
        url = source.get("url", "")
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list):
            return data
        return data.get("alerts", [data])

    def _fetch_file(self, source: dict) -> list[dict]:
        path = Path(source.get("path", ""))
        if not path.exists():
            return []
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        return data.get("alerts", [data])

    def _fetch_prometheus(self, source: dict) -> list[dict]:
        url = source.get("url", "http://localhost:9090")
        query = source.get("query", 'ALERTS{alertstate="firing"}')
        resp = requests.get(f"{url}/api/v1/query", params={"query": query}, timeout=10)
        resp.raise_for_status()
        results = resp.json().get("data", {}).get("result", [])
        return [{"labels": r.get("metric", {}), "value": r.get("value", [])} for r in results]

    def _fetch_datadog(self, source: dict) -> list[dict]:
        api_key = source.get("api_key", "")
        app_key = source.get("app_key", "")
        base_url = source.get("base_url", "https://api.datadoghq.com")
        query = source.get("query", "status:fired")
        days_back = source.get("days_back", 1)

        headers = {"DD-APPLICATION-KEY": app_key, "DD-API-KEY": api_key}
        resp = requests.get(
            f"{base_url}/api/v1/events",
            headers=headers,
            params={"query": query, "days_back": days_back},
            timeout=15,
        )
        resp.raise_for_status()
        events = resp.json().get("events", [])
        alerts = []
        for event in events:
            alert = {
                "source": "datadog",
                "title": event.get("title", "Datadog Alert"),
                "description": event.get("text", ""),
                "severity": event.get("priority", "warning"),
                "timestamp": event.get("date_happened"),
                "service": event.get("tags", {}).get("service", "unknown")
                if isinstance(event.get("tags"), dict)
                else "",
                "tags": event.get("tags", []),
            }
            alerts.append(alert)
        return alerts

    def _fetch_pagerduty(self, source: dict) -> list[dict]:
        routing_key = source.get("routing_key", "")
        base_url = source.get("base_url", "https://api.pagerduty.com")

        headers = {
            "Authorization": f"Token token={routing_key}",
            "Accept": "application/vnd.pagerduty+json;version=2",
        }
        resp = requests.get(
            f"{base_url}/incidents",
            headers=headers,
            params={"status": "triggered", "limit": 50},
            timeout=15,
        )
        resp.raise_for_status()
        incidents = resp.json().get("incidents", [])
        alerts = []
        for inc in incidents:
            alert = {
                "source": "pagerduty",
                "title": inc.get("title", "PagerDuty Incident"),
                "description": inc.get("description", ""),
                "severity": inc.get("urgency", "warning"),
                "timestamp": inc.get("created_at"),
                "service": inc.get("service", {}).get("summary", "unknown"),
                "incident_number": inc.get("incident_number"),
                "html_url": inc.get("html_url"),
            }
            alerts.append(alert)
        return alerts

    def _fetch_slack_webhook(self, source: dict) -> list[dict]:
        webhook_url = source.get("webhook_url", "")
        resp = requests.get(webhook_url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        alerts = []
        if isinstance(data, list):
            for item in data:
                alerts.append(self._parse_slack_message(item))
        elif isinstance(data, dict):
            alerts.append(self._parse_slack_message(data))
        return alerts

    def _parse_slack_message(self, message: dict) -> dict:
        text = message.get("text", "")
        return {
            "source": "slack",
            "title": text[:100] if text else "Slack Alert",
            "description": text,
            "severity": "warning",
            "timestamp": message.get("ts", datetime.now(timezone.utc).isoformat()),
            "service": message.get("channel", "unknown"),
            "raw": message,
        }

    def _fetch_healthcheck(self, source: dict) -> list[dict]:
        endpoints = source.get("endpoints", [])
        alerts = []
        for ep in endpoints:
            url = ep.get("url", "")
            service = ep.get("service", "unknown")
            timeout_seconds = ep.get("timeout", 10)
            expected_status = ep.get("expected_status", 200)
            try:
                resp = requests.get(url, timeout=timeout_seconds)
                if resp.status_code != expected_status:
                    alerts.append(
                        {
                            "source": "healthcheck",
                            "title": f"Health check failed: {service}",
                            "description": f"Expected status {expected_status}, got {resp.status_code} from {url}",
                            "severity": "critical" if resp.status_code >= 500 else "warning",
                            "service": service,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "status_code": resp.status_code,
                            "url": url,
                        }
                    )
            except requests.exceptions.Timeout:
                alerts.append(
                    {
                        "source": "healthcheck",
                        "title": f"Health check timeout: {service}",
                        "description": f"Health check timed out after {timeout_seconds}s at {url}",
                        "severity": "critical",
                        "service": service,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "url": url,
                    }
                )
            except requests.exceptions.ConnectionError:
                alerts.append(
                    {
                        "source": "healthcheck",
                        "title": f"Health check connection failed: {service}",
                        "description": f"Could not connect to health endpoint at {url}",
                        "severity": "critical",
                        "service": service,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "url": url,
                    }
                )
        return alerts

    def _is_new(self, alert: dict) -> bool:
        h = hashlib.md5(json.dumps(alert, sort_keys=True, default=str).encode()).hexdigest()
        if h in self._seen_hashes:
            return False
        self._seen_hashes.add(h)
        return True
