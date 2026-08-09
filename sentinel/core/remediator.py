"""Remediation engine — executes or simulates incident remediation."""

from __future__ import annotations
import json
import subprocess
from pathlib import Path
from typing import Any


class RemediationEngine:
    def __init__(self, config: dict, display: Any = None):
        self.config = config
        self.display = display
        self.incidents_dir = Path("data/incidents")

    def remediate(self, incident_id: str, dry_run: bool = False) -> bool:
        incident = self._load_incident(incident_id)
        if not incident:
            if self.display:
                self.display.print_error(f"Incident {incident_id} not found.")
            return False

        steps = incident.get("remediation_steps", [])
        if not steps:
            if self.display:
                self.display.print_error("No remediation steps defined.")
            return False

        if self.display:
            self.display.print_step(f"Remediating {incident_id} ({len(steps)} steps) {'[DRY RUN]' if dry_run else ''}")

        all_ok = True
        for step in sorted(steps, key=lambda s: s.get("order", 99)):
            action = step.get("action", "")
            command = step.get("command", "")
            risk = step.get("risk", "low")

            if self.display:
                self.display.print_step(f"  Step {step.get('order', '?')}: {action} [risk: {risk}]")

            if dry_run:
                if command:
                    if self.display:
                        self.display.print_step(f"    Would execute: {command}")
                continue

            if command and risk in ("low", "medium"):
                ok = self._execute_command(command)
                if not ok:
                    all_ok = False
                    if self.display:
                        self.display.print_step(f"    Command failed: {command}")
            elif command and risk == "high":
                if self.display:
                    self.display.print_step(f"    Skipping high-risk command (requires manual approval): {command}")

        return all_ok

    def _load_incident(self, incident_id: str) -> dict | None:
        path = self.incidents_dir / f"{incident_id}.json"
        if path.exists():
            with open(path) as f:
                return json.load(f)
        return None

    def _execute_command(self, command: str) -> bool:
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=60,
            )
            if result.returncode != 0:
                if self.display:
                    self.display.print_step(f"    stderr: {result.stderr[:200]}")
                return False
            return True
        except subprocess.TimeoutExpired:
            return False
        except Exception:
            return False
