"""Alert manager — watches for alerts from various sources."""

from __future__ import annotations
import json
import time
import requests
from pathlib import Path
from typing import Any

from sentinel.core.analyzer import IncidentAnalyzer


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
                self.display.print_step("No alert sources configured. Add sources to config/sentinel.json")
                self.display.print_step("Example config:")
                self.display.print_step(json.dumps({
                    "alert_sources": [
                        {"type": "webhook", "url": "http://localhost:9090/api/v1/alerts"},
                        {"type": "file", "path": "data/alerts.json"},
                    ]
                }, indent=2))
            return

        while True:
            for source in self.sources:
                alerts = self._fetch_alerts(source)
                for alert in alerts:
                    if self._is_new(alert):
                        if self.display:
                            self.display.print_step(f"New alert from {source.get('type', 'unknown')}")
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
        query = source.get("query", "ALERTS{alertstate=\"firing\"}")
        resp = requests.get(f"{url}/api/v1/query", params={"query": query}, timeout=10)
        resp.raise_for_status()
        results = resp.json().get("data", {}).get("result", [])
        return [{"labels": r.get("metric", {}), "value": r.get("value", [])} for r in results]

    def _is_new(self, alert: dict) -> bool:
        import hashlib
        h = hashlib.md5(json.dumps(alert, sort_keys=True, default=str).encode()).hexdigest()
        if h in self._seen_hashes:
            return False
        self._seen_hashes.add(h)
        return True
