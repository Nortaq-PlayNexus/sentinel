"""Postmortem generator - create postmortem documents from incident data."""

from __future__ import annotations
from datetime import datetime, timezone
from typing import Any


class PostmortemGenerator:
    def __init__(self, display: Any = None):
        self.display = display

    def generate(self, incident: dict) -> str:
        title = incident.get("title", "Incident Postmortem")
        severity = incident.get("severity", "P3")
        incident_id = incident.get("incident_id", "UNKNOWN")
        root_cause = incident.get("root_cause", "Unknown")
        impact = incident.get("impact", {})
        services = impact.get("affected_services", [])
        timeline = incident.get("timeline", [])
        remediation_steps = incident.get("remediation_steps", [])
        prevention = incident.get("prevention", [])

        mttr = self._calculate_mttr(incident)
        created_at = incident.get("timestamp", "")
        duration_str = self._format_duration(mttr)

        summary = self._build_summary(impact, services, severity, root_cause)

        timeline_section = self._build_timeline_section(timeline)

        root_cause_section = self._build_root_cause_section(root_cause, incident)

        impact_section = self._build_impact_section(impact, services, severity, mttr)

        action_items = self._build_action_items(incident, remediation_steps, prevention)

        lessons = self._build_lessons_learned(incident, root_cause, severity)

        lines = [
            f"# Postmortem: {title}",
            "",
            f"**Incident ID:** {incident_id}",
            f"**Date:** {created_at or datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"**Severity:** {severity}",
            f"**Duration:** {duration_str}",
            f"**MTTR:** {mttr} seconds",
            "",
            "---",
            "",
            "## Summary",
            "",
            summary,
            "",
            "---",
            "",
            "## Timeline",
            "",
            timeline_section,
            "",
            "---",
            "",
            "## Root Cause Analysis",
            "",
            root_cause_section,
            "",
            "---",
            "",
            "## Impact",
            "",
            impact_section,
            "",
            "---",
            "",
            "## Action Items",
            "",
            action_items,
            "",
            "---",
            "",
            "## Lessons Learned",
            "",
            lessons,
            "",
            "---",
            "",
            "## Appendix",
            "",
            "- Related alerts and monitoring dashboards",
            "- Deployment history and change logs",
            "- Communication logs (Slack, PagerDuty, etc.)",
            "",
        ]
        return "\n".join(lines)

    def _calculate_mttr(self, incident: dict) -> float:
        timeline = incident.get("timeline", [])
        if len(timeline) < 2:
            return 0.0

        timestamps = []
        for entry in timeline:
            ts = entry.get("time", "")
            if ts:
                try:
                    if isinstance(ts, str):
                        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    else:
                        dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
                    timestamps.append(dt)
                except (ValueError, TypeError, OSError):
                    pass

        if len(timestamps) < 2:
            return 0.0

        earliest = min(timestamps)
        latest = max(timestamps)
        delta = (latest - earliest).total_seconds()
        return round(delta, 2)

    def _format_duration(self, seconds: float) -> str:
        if seconds < 60:
            return f"{seconds:.0f} seconds"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f} minutes"
        else:
            hours = seconds / 3600
            return f"{hours:.1f} hours"

    def _build_summary(
        self, impact: dict, services: list[str], severity: str, root_cause: str
    ) -> str:
        parts = []
        if severity in ("P1", "P2"):
            parts.append("A high-severity incident occurred")
        else:
            parts.append("An incident occurred")

        if services:
            parts.append(f"affecting the following services: {', '.join(services)}")

        blast = impact.get("blast_radius", "")
        if blast:
            parts.append(f"The blast radius was: {blast}")

        if root_cause and root_cause != "Unknown":
            parts.append(f"The root cause was identified as: {root_cause}")

        downtime = impact.get("estimated_downtime", "")
        if downtime and downtime != "Unknown":
            parts.append(f"Estimated downtime: {downtime}")

        return ". ".join(parts) + "."

    def _build_timeline_section(self, timeline: list[dict]) -> str:
        if not timeline:
            return "No timeline data available."

        lines = []
        for entry in sorted(timeline, key=lambda x: x.get("time", "")):
            time_str = entry.get("time", "Unknown time")
            event = entry.get("event", "Unknown event")
            lines.append(f"- **{time_str}** - {event}")
        return "\n".join(lines)

    def _build_root_cause_section(self, root_cause: str, incident: dict) -> str:
        lines = [
            f"**Root Cause:** {root_cause}",
            "",
        ]

        services = incident.get("impact", {}).get("affected_services", [])
        if services:
            lines.append(f"**Affected Components:** {', '.join(services)}")

        dependencies = incident.get("correlations", {}).get("by_dependency", {})
        if dependencies:
            lines.append("")
            lines.append("**Service Dependencies Involved:**")
            for dep, alerts in dependencies.items():
                lines.append(f"- {dep} ({len(alerts)} related alert(s))")

        return "\n".join(lines)

    def _build_impact_section(
        self, impact: dict, services: list[str], severity: str, mttr: float
    ) -> str:
        lines = [
            "| Metric | Value |",
            "|--------|-------|",
            f"| Severity | {severity} |",
            f"| Affected Services | {', '.join(services) if services else 'Unknown'} |",
            f"| Blast Radius | {impact.get('blast_radius', 'Unknown')} |",
            f"| Estimated Downtime | {impact.get('estimated_downtime', 'Unknown')} |",
            f"| Mean Time To Resolve (MTTR) | {self._format_duration(mttr)} |",
        ]
        return "\n".join(lines)

    def _build_action_items(
        self, incident: dict, remediation_steps: list[dict], prevention: list[str]
    ) -> str:
        lines = []
        item_num = 1

        if remediation_steps:
            lines.append("**Immediate (completed during incident):**")
            for step in sorted(remediation_steps, key=lambda s: s.get("order", 99)):
                action = step.get("action", "")
                lines.append(f"{item_num}. [x] {action}")
                item_num += 1
            lines.append("")

        lines.append("**Short-term (within 1 week):**")
        lines.append(f"{item_num}. [ ] Create monitoring dashboard for affected services")
        item_num += 1
        lines.append(f"{item_num}. [ ] Add alerting for root cause indicators")
        item_num += 1
        lines.append(f"{item_num}. [ ] Review and update runbooks based on this incident")
        item_num += 1
        lines.append("")

        lines.append("**Long-term (within 1 month):**")
        lines.append(f"{item_num}. [ ] Implement automated remediation for this failure mode")
        item_num += 1
        lines.append(f"{item_num}. [ ] Conduct chaos engineering tests for this scenario")
        item_num += 1

        if prevention:
            lines.append("")
            lines.append("**Prevention recommendations:**")
            for p in prevention:
                lines.append(f"{item_num}. [ ] {p}")
                item_num += 1

        return "\n".join(lines)

    def _build_lessons_learned(self, incident: dict, root_cause: str, severity: str) -> str:
        lines = []

        lines.append("**What went well:**")
        lines.append("- Incident was detected and escalated promptly")
        lines.append("- Root cause was identified and communicated")
        lines.append("- Remediation steps were executed successfully")
        lines.append("")

        lines.append("**What could be improved:**")
        lines.append("- Detection time could be reduced with better alerting")
        lines.append("- Automated remediation would reduce MTTR")
        lines.append("- Better runbooks would speed up diagnosis")
        lines.append("")

        lines.append("**Where we got lucky:**")
        if severity in ("P1", "P2"):
            lines.append(
                "- The incident occurred during business hours when more engineers were available"
            )
        else:
            lines.append("- The impact was limited to a subset of users")
            lines.append("- No data loss occurred")

        return "\n".join(lines)
