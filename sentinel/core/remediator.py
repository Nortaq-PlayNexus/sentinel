"""Remediation engine - executes or simulates incident remediation."""

from __future__ import annotations
import json
import subprocess
from pathlib import Path
from typing import Any


REMEDIATION_ACTIONS = {
    "restart_service": {
        "description": "Restart a systemd/docker service",
        "risk_level": "medium",
        "requires_confirmation": True,
    },
    "scale_instances": {
        "description": "Scale up/down service instances",
        "risk_level": "high",
        "requires_confirmation": True,
    },
    "rollback_deployment": {
        "description": "Rollback to previous deployment version",
        "risk_level": "high",
        "requires_confirmation": True,
    },
    "clear_cache": {
        "description": "Clear Redis/memcached cache",
        "risk_level": "medium",
        "requires_confirmation": True,
    },
    "increase_connections": {
        "description": "Increase DB connection pool size",
        "risk_level": "medium",
        "requires_confirmation": True,
    },
    "enable_maintenance_mode": {
        "description": "Put service in maintenance mode",
        "risk_level": "low",
        "requires_confirmation": True,
    },
}


class RemediationEngine:
    def __init__(self, config: dict, display: Any = None):
        self.config = config
        self.display = display
        self.incidents_dir = Path("data/incidents")
        self.dry_run = False

    def remediate(self, incident_id: str, dry_run: bool = False) -> bool:
        self.dry_run = dry_run
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
            self.display.print_step(
                f"Remediating {incident_id} ({len(steps)} steps) {'[DRY RUN]' if dry_run else ''}"
            )

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
                    self.display.print_step(
                        f"    Skipping high-risk command (requires manual approval): {command}"
                    )

        return all_ok

    def restart_service(self, service_name: str, use_docker: bool = False) -> bool:
        action_meta = REMEDIATION_ACTIONS["restart_service"]
        if not self._confirm_action(f"Restart service '{service_name}'", action_meta):
            return False

        if use_docker:
            cmd = f"docker restart {service_name}"
        else:
            cmd = f"systemctl restart {service_name}"

        if self.dry_run:
            if self.display:
                self.display.print_step(f"    Would execute: {cmd}")
            return True
        return self._execute_command(cmd)

    def scale_instances(self, service: str, count: int) -> bool:
        action_meta = REMEDIATION_ACTIONS["scale_instances"]
        if not self._confirm_action(f"Scale '{service}' to {count} instances", action_meta):
            return False

        cmd = f"docker service scale {service}={count}"
        if self.dry_run:
            if self.display:
                self.display.print_step(f"    Would execute: {cmd}")
            return True
        return self._execute_command(cmd)

    def rollback_deployment(self, service: str, version: str = "previous") -> bool:
        action_meta = REMEDIATION_ACTIONS["rollback_deployment"]
        if not self._confirm_action(f"Rollback '{service}' to {version}", action_meta):
            return False

        if version == "previous":
            cmd = f"kubectl rollout undo deployment/{service}"
        else:
            cmd = f"kubectl rollout undo deployment/{service} --to-revision={version}"

        if self.dry_run:
            if self.display:
                self.display.print_step(f"    Would execute: {cmd}")
            return True
        return self._execute_command(cmd)

    def clear_cache(self, service: str, cache_type: str = "redis") -> bool:
        action_meta = REMEDIATION_ACTIONS["clear_cache"]
        if not self._confirm_action(f"Clear {cache_type} cache for '{service}'", action_meta):
            return False

        if cache_type == "redis":
            cmd = "redis-cli FLUSHALL"
        elif cache_type == "memcached":
            cmd = "echo 'flush_all' | nc localhost 11211"
        else:
            cmd = f"echo 'Unsupported cache type: {cache_type}'"
            if self.display:
                self.display.print_error(cmd)
            return False

        if self.dry_run:
            if self.display:
                self.display.print_step(f"    Would execute: {cmd}")
            return True
        return self._execute_command(cmd)

    def increase_connections(self, service: str, pool_size: int) -> bool:
        action_meta = REMEDIATION_ACTIONS["increase_connections"]
        if not self._confirm_action(
            f"Increase connection pool to {pool_size} for '{service}'", action_meta
        ):
            return False

        cmd = f'psql -c "ALTER SYSTEM SET max_connections = {pool_size}; SELECT pg_reload_conf();"'
        if self.dry_run:
            if self.display:
                self.display.print_step(f"    Would execute: {cmd}")
            return True
        return self._execute_command(cmd)

    def enable_maintenance_mode(self, service: str) -> bool:
        action_meta = REMEDIATION_ACTIONS["enable_maintenance_mode"]
        if not self._confirm_action(f"Enable maintenance mode for '{service}'", action_meta):
            return False

        cmd = f"touch /tmp/{service}.maintenance"
        if self.dry_run:
            if self.display:
                self.display.print_step(f"    Would execute: {cmd}")
            return True
        return self._execute_command(cmd)

    def _confirm_action(self, description: str, action_meta: dict) -> bool:
        if self.dry_run:
            return True
        if not action_meta.get("requires_confirmation", False):
            return True
        if self.display:
            self.display.print_step(
                f"  [CONFIRM] {description} (risk: {action_meta['risk_level']})"
            )
        return True

    def _load_incident(self, incident_id: str) -> dict | None:
        path = self.incidents_dir / f"{incident_id}.json"
        if path.exists():
            with open(path) as f:
                return json.load(f)
        return None

    def _execute_command(self, command: str) -> bool:
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=60,
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
