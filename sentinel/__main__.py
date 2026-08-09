"""Sentinel — CLI entry point."""

import argparse
import sys
import json
from pathlib import Path

from sentinel import __version__
from sentinel.core.analyzer import IncidentAnalyzer
from sentinel.core.remediator import RemediationEngine
from sentinel.core.alerts import AlertManager
from sentinel.ui.display import Display


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="AI Incident Commander — detect, diagnose, and remediate production incidents.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    diagnose = sub.add_parser("diagnose", help="Diagnose an incident from alert data")
    diagnose.add_argument("input", nargs="?", help="JSON file or inline JSON alert")
    diagnose.add_argument("--format", choices=["json", "text"], default="text")

    remediate = sub.add_parser("remediate", help="Execute remediation for a diagnosed incident")
    remediate.add_argument("incident_id", type=str, help="Incident ID to remediate")
    remediate.add_argument("--dry-run", action="store_true", help="Show what would be done")

    watch = sub.add_parser("watch", help="Watch for alerts from configured sources")
    watch.add_argument("--config", type=str, default="config/sentinel.json")
    watch.add_argument("--interval", type=int, default=30, help="Poll interval in seconds")

    report = sub.add_parser("report", help="Generate incident report")
    report.add_argument("incident_id", type=str, help="Incident ID")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    display = Display()

    if not args.command:
        parser.print_help()
        return 0

    config = {}
    config_path = Path("config/sentinel.json")
    if config_path.exists():
        with open(config_path) as f:
            config = json.load(f)

    if args.command == "diagnose":
        input_data = args.input
        if input_data and Path(input_data).exists():
            with open(input_data) as f:
                alert_data = json.load(f)
        elif input_data:
            alert_data = json.loads(input_data)
        else:
            display.print_error("Provide a JSON file or inline JSON.")
            return 1

        analyzer = IncidentAnalyzer(config, display)
        incident = analyzer.analyze(alert_data)
        display.print_incident(incident)
        return 0

    if args.command == "remediate":
        engine = RemediationEngine(config, display)
        result = engine.remediate(args.incident_id, dry_run=args.dry_run)
        if result:
            display.print_success("Remediation complete.")
        else:
            display.print_error("Remediation failed.")
        return 0 if result else 1

    if args.command == "watch":
        manager = AlertManager(config, display)
        manager.watch(interval=args.interval)
        return 0

    if args.command == "report":
        display.print_error("Report generation not yet implemented.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
