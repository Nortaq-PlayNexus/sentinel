"""Rich CLI display for Sentinel."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown
from rich import box


console = Console()


class Display:
    def print_step(self, message: str):
        console.print(f"  [bold blue]->[/bold blue] {message}")

    def print_success(self, message: str):
        console.print(f"  [bold green]+[/bold green] {message}")

    def print_error(self, message: str):
        console.print(f"  [bold red]x[/bold red] {message}")

    def print_incident(self, incident: dict):
        console.print()
        severity = incident.get("severity", "P3")
        sev_color = {"P1": "red", "P2": "dark_orange", "P3": "yellow", "P4": "green"}.get(severity, "yellow")

        console.print(
            Panel(
                f"[bold {sev_color}]{severity}[/bold {sev_color}] -- {incident.get('title', 'Incident')}\n"
                f"ID: {incident.get('incident_id', 'unknown')}\n"
                f"Root Cause: {incident.get('root_cause', 'N/A')}",
                border_style=sev_color, expand=True,
            )
        )

        impact = incident.get("impact", {})
        if impact:
            table = Table(box=box.SIMPLE_HEAVY, title="Impact Assessment")
            table.add_column("Field", style="bold")
            table.add_column("Value")
            table.add_row("Severity", impact.get("severity", "-"))
            table.add_row("Affected Services", ", ".join(impact.get("affected_services", [])))
            table.add_row("Blast Radius", impact.get("blast_radius", "-"))
            table.add_row("Est. Downtime", impact.get("estimated_downtime", "-"))
            console.print(table)

        steps = incident.get("remediation_steps", [])
        if steps:
            console.print()
            st = Table(box=box.ROUNDED, title="Remediation Steps")
            st.add_column("#", style="dim", width=3)
            st.add_column("Action")
            st.add_column("Risk", style="bold")
            st.add_column("Command", style="dim")
            for s in sorted(steps, key=lambda x: x.get("order", 99)):
                risk = s.get("risk", "low")
                risk_style = {"low": "green", "medium": "yellow", "high": "red"}.get(risk, "white")
                st.add_row(
                    str(s.get("order", "?")),
                    s.get("action", ""),
                    f"[{risk_style}]{risk}[/{risk_style}]",
                    s.get("command", "-"),
                )
            console.print(st)

        prevention = incident.get("prevention", [])
        if prevention:
            console.print()
            console.print("[bold]Prevention:[/bold]")
            for p in prevention:
                console.print(f"  - {p}")

        console.print()

    def print_timeline(self, timeline: list[dict]):
        console.print()
        console.print(Panel("[bold]Incident Timeline[/bold]", border_style="blue", expand=True))
        console.print()

        if not timeline:
            console.print("  [dim]No timeline data available.[/dim]")
            console.print()
            return

        sorted_timeline = sorted(timeline, key=lambda x: x.get("time", ""))
        for i, entry in enumerate(sorted_timeline):
            time_str = entry.get("time", "Unknown")
            event = entry.get("event", "Unknown event")
            connector = "+--" if i < len(sorted_timeline) - 1 else "`--"
            console.print(f"  [dim]{connector}[/dim] [bold]{time_str}[/bold]")
            console.print(f"  {'|' if i < len(sorted_timeline) - 1 else ' '}   {event}")
            if i < len(sorted_timeline) - 1:
                console.print(f"  [dim]|[/dim]")

        console.print()

    def print_runbook(self, runbook_markdown: str):
        console.print()
        console.print(Panel("[bold]Runbook[/bold]", border_style="cyan", expand=True))
        console.print()
        md = Markdown(runbook_markdown)
        console.print(md)
        console.print()

    def print_postmortem(self, postmortem_markdown: str):
        console.print()
        console.print(Panel("[bold]Postmortem Report[/bold]", border_style="magenta", expand=True))
        console.print()
        md = Markdown(postmortem_markdown)
        console.print(md)
        console.print()

    def print_correlation_graph(self, correlations: dict):
        console.print()
        console.print(Panel("[bold]Alert Correlations[/bold]", border_style="yellow", expand=True))
        console.print()

        by_service = correlations.get("by_service", {})
        if by_service:
            console.print("[bold]  By Service:[/bold]")
            for svc, alerts in by_service.items():
                console.print(f"    [cyan]{svc}[/cyan] ({len(alerts)} alert(s))")
                for alert in alerts:
                    title = alert.get("title", alert.get("summary", "alert"))
                    console.print(f"      - {title}")
            console.print()

        by_time = correlations.get("by_time_window", {})
        if by_time:
            console.print("[bold]  By Time Window:[/bold]")
            for window, alerts in by_time.items():
                console.print(f"    [yellow]{window}[/yellow] ({len(alerts)} alert(s))")
            console.print()

        by_dep = correlations.get("by_dependency", {})
        if by_dep:
            console.print("[bold]  By Service Dependency:[/bold]")
            for dep, alerts in by_dep.items():
                console.print(f"    [red]{dep}[/red] ({len(alerts)} alert(s))")
            console.print()

        if not by_service and not by_time and not by_dep:
            console.print("  [dim]No correlations found.[/dim]")

        console.print()
