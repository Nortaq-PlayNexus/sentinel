"""Runbook generator - auto-generate runbooks from incidents or templates."""

from __future__ import annotations
from datetime import datetime, timezone
from typing import Any


TEMPLATE_RUNBOOKS = {
    "service_down": {
        "title": "Service Down Runbook",
        "symptoms": [
            "HTTP 503/502 errors from load balancer",
            "Health check failures",
            "Users reporting service unavailable",
            "Monitoring alerts for service status",
        ],
        "diagnosis": [
            "Check service process status: `systemctl status <service>`",
            "Check recent deployments: `git log --oneline -10`",
            "Check service logs: `journalctl -u <service> --since '30 min ago'`",
            "Check resource usage: `top -bn1 | head -20`",
            "Check port binding: `ss -tuln | grep <port>`",
        ],
        "remediation": [
            {
                "order": 1,
                "action": "Restart the service",
                "command": "systemctl restart <service>",
                "risk": "medium",
            },
            {
                "order": 2,
                "action": "If restart fails, check disk space",
                "command": "df -h",
                "risk": "low",
            },
            {
                "order": 3,
                "action": "If disk full, clean logs",
                "command": "journalctl --vacuum-time=3d",
                "risk": "medium",
            },
            {
                "order": 4,
                "action": "Rollback if recent deployment",
                "command": "git revert HEAD --no-edit",
                "risk": "high",
            },
        ],
        "verification": [
            "Health check returns 200",
            "Error rate returns to baseline",
            "Users confirm service is accessible",
            "Monitoring dashboards show green",
        ],
        "escalation": [
            "On-call engineer if not resolved in 15 min",
            "Team lead if not resolved in 30 min",
            "Engineering manager if customer impact > 30 min",
        ],
    },
    "high_latency": {
        "title": "High Latency Runbook",
        "symptoms": [
            "P99/P95 latency above SLA threshold",
            "Users reporting slow responses",
            "Request queue buildup",
            "Timeout errors increasing",
        ],
        "diagnosis": [
            "Check current latency metrics: `curl -s localhost:<port>/metrics | grep latency`",
            "Identify slow endpoints in APM",
            "Check database query performance",
            "Check for resource contention: `top -bn1`",
            "Check network latency: `ping <dependency>`",
        ],
        "remediation": [
            {
                "order": 1,
                "action": "Scale up instances",
                "command": "docker service scale <service>=<count>",
                "risk": "medium",
            },
            {
                "order": 2,
                "action": "Enable caching if applicable",
                "command": "",
                "risk": "low",
            },
            {
                "order": 3,
                "action": "Check and optimize slow queries",
                "command": "",
                "risk": "low",
            },
            {
                "order": 4,
                "action": "Increase connection pool",
                "command": "",
                "risk": "medium",
            },
        ],
        "verification": [
            "Latency metrics return to baseline",
            "Error rate remains low",
            "User reports of slowness stop",
        ],
        "escalation": [
            "On-call engineer if latency > 2x baseline for 10 min",
            "Team lead if user impact confirmed",
        ],
    },
    "memory_leak": {
        "title": "Memory Leak Runbook",
        "symptoms": [
            "Memory usage steadily increasing over time",
            "OOM kills in dmesg/logs",
            "Service restarts due to OOM",
            "Swap usage increasing",
        ],
        "diagnosis": [
            "Check current memory usage: `free -h`",
            "Identify top memory consumers: `ps aux --sort=-%mem | head -20`",
            "Check OOM killer logs: `dmesg | grep -i oom`",
            "Profile application memory if possible",
            "Check for memory growth trend in monitoring",
        ],
        "remediation": [
            {
                "order": 1,
                "action": "Restart affected service",
                "command": "systemctl restart <service>",
                "risk": "medium",
            },
            {
                "order": 2,
                "action": "Increase memory limits",
                "command": "",
                "risk": "medium",
            },
            {
                "order": 3,
                "action": "Enable memory profiling",
                "command": "",
                "risk": "low",
            },
            {
                "order": 4,
                "action": "Scale horizontally to distribute load",
                "command": "docker service scale <service>=<count>",
                "risk": "medium",
            },
        ],
        "verification": [
            "Memory usage stabilizes after restart",
            "No new OOM kills",
            "Memory growth trend in monitoring stops",
        ],
        "escalation": [
            "On-call engineer immediately for OOM kills",
            "Team lead if OOM kills repeat within 1 hour",
        ],
    },
    "disk_full": {
        "title": "Disk Full Runbook",
        "symptoms": [
            "No space left on device errors",
            "Write failures in application logs",
            "Database unable to write",
            "Disk usage alerts firing",
        ],
        "diagnosis": [
            "Check disk usage: `df -h`",
            "Find largest directories: `du -sh /* | sort -rh | head -20`",
            "Find largest files: `find / -type f -exec du -h {} + 2>/dev/null | sort -rh | head -20`",
            "Check for log rotation issues: `ls -la /var/log/`",
            "Check for temp files: `ls -la /tmp/`",
        ],
        "remediation": [
            {
                "order": 1,
                "action": "Clean old logs",
                "command": "find /var/log -name '*.log' -mtime +7 -delete",
                "risk": "medium",
            },
            {
                "order": 2,
                "action": "Clean temp files",
                "command": "find /tmp -type f -mtime +1 -delete",
                "risk": "low",
            },
            {
                "order": 3,
                "action": "Vacuum journal logs",
                "command": "journalctl --vacuum-time=3d",
                "risk": "medium",
            },
            {
                "order": 4,
                "action": "Clean Docker images",
                "command": "docker system prune -f",
                "risk": "medium",
            },
        ],
        "verification": [
            "Disk usage below 80%",
            "Write operations succeed",
            "No new disk full errors",
        ],
        "escalation": [
            "On-call engineer if disk full affects service",
            "Team lead if database is affected",
        ],
    },
    "deploy_failure": {
        "title": "Deploy Failure Runback",
        "symptoms": [
            "Deployment pipeline failing",
            "Health checks failing after deploy",
            "New errors in logs after deploy",
            "User-reported regressions after deploy",
        ],
        "diagnosis": [
            "Check deployment logs for errors",
            "Verify build artifacts",
            "Check health endpoints post-deploy",
            "Compare pre/post deploy metrics",
            "Review recent code changes",
        ],
        "remediation": [
            {
                "order": 1,
                "action": "Rollback to previous version",
                "command": "kubectl rollout undo deployment/<service>",
                "risk": "high",
            },
            {
                "order": 2,
                "action": "Verify rollback health",
                "command": "",
                "risk": "low",
            },
            {
                "order": 3,
                "action": "Notify team of rollback",
                "command": "",
                "risk": "low",
            },
            {
                "order": 4,
                "action": "Create incident ticket for root cause",
                "command": "",
                "risk": "low",
            },
        ],
        "verification": [
            "Service returns to pre-deploy state",
            "Health checks passing",
            "No new errors in logs",
            "User reports resolved",
        ],
        "escalation": [
            "On-call engineer immediately",
            "Team lead if customer impact",
            "Engineering manager if P1",
        ],
    },
}


class RunbookGenerator:
    def __init__(self, display: Any = None):
        self.display = display

    def generate_from_incident(self, incident: dict) -> str:
        title = incident.get("title", "Incident Runbook")
        severity = incident.get("severity", "P3")
        root_cause = incident.get("root_cause", "Unknown")
        services = incident.get("impact", {}).get("affected_services", [])
        remediation_steps = incident.get("remediation_steps", [])
        timeline = incident.get("timeline", [])

        symptoms = []
        for entry in timeline:
            event = entry.get("event", "")
            if event:
                symptoms.append(event)

        if not symptoms:
            symptoms = [
                f"Alerts firing for {', '.join(services)}"
                if services
                else "Multiple alerts detected",
                f"Root cause identified: {root_cause}",
            ]

        diagnosis_steps = [
            "Review incident timeline and related alerts",
            f"Check health of affected services: {', '.join(services)}"
            if services
            else "Check health of affected services",
            "Review recent changes and deployments",
            "Check resource utilization (CPU, memory, disk, network)",
        ]

        verification = [
            "Service health checks returning 200",
            "Error rate returns to baseline",
            "No new alerts firing for affected services",
            "User-reported issues resolved",
        ]

        escalation = [
            f"On-call engineer - immediate for {severity}"
            if severity in ("P1", "P2")
            else "On-call engineer - within 30 min",
            "Team lead - if not resolved in 30 min",
            "Engineering manager - if customer impact > 1 hour",
        ]

        lines = [
            f"# Runbook: {title}",
            "",
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"**Severity:** {severity}",
            f"**Affected Services:** {', '.join(services) if services else 'Unknown'}",
            "",
            "---",
            "",
            "## Symptoms",
            "",
        ]
        for s in symptoms:
            lines.append(f"- {s}")

        lines.extend(["", "## Diagnosis Steps", ""])
        for i, step in enumerate(diagnosis_steps, 1):
            lines.append(f"{i}. {step}")

        if remediation_steps:
            lines.extend(["", "## Remediation Steps", ""])
            for step in sorted(remediation_steps, key=lambda s: s.get("order", 99)):
                risk = step.get("risk", "low")
                cmd = step.get("command", "")
                action = step.get("action", "")
                risk_badge = f" `[risk: {risk}]`" if risk != "low" else ""
                lines.append(f"{step.get('order', '?')}. {action}{risk_badge}")
                if cmd:
                    lines.append(f"   ```bash\n   {cmd}\n   ```")

        lines.extend(["", "## Verification", ""])
        for i, v in enumerate(verification, 1):
            lines.append(f"{i}. {v}")

        lines.extend(["", "## Escalation", ""])
        for e in escalation:
            lines.append(f"- {e}")

        lines.append("")
        return "\n".join(lines)

    def generate_from_template(self, template_name: str) -> str:
        template = TEMPLATE_RUNBOOKS.get(template_name)
        if not template:
            available = ", ".join(TEMPLATE_RUNBOOKS.keys())
            return f"Unknown template '{template_name}'. Available: {available}"

        lines = [
            f"# {template['title']}",
            "",
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            "---",
            "",
            "## Symptoms",
            "",
        ]
        for s in template.get("symptoms", []):
            lines.append(f"- {s}")

        lines.extend(["", "## Diagnosis Steps", ""])
        for i, step in enumerate(template.get("diagnosis", []), 1):
            lines.append(f"{i}. {step}")

        lines.extend(["", "## Remediation Steps", ""])
        for step in template.get("remediation", []):
            risk = step.get("risk", "low")
            cmd = step.get("command", "")
            action = step.get("action", "")
            risk_badge = f" `[risk: {risk}]`" if risk != "low" else ""
            lines.append(f"{step.get('order', '?')}. {action}{risk_badge}")
            if cmd:
                lines.append(f"   ```bash\n   {cmd}\n   ```")

        lines.extend(["", "## Verification", ""])
        for i, v in enumerate(template.get("verification", []), 1):
            lines.append(f"{i}. {v}")

        lines.extend(["", "## Escalation", ""])
        for e in template.get("escalation", []):
            lines.append(f"- {e}")

        lines.append("")
        return "\n".join(lines)

    def list_templates(self) -> list[str]:
        return list(TEMPLATE_RUNBOOKS.keys())
