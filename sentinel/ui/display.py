"""Rich CLI display for Sentinel."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box


console = Console()


class Display:
    def print_step(self, message: str):
        console.print(f"  [bold blue]→[/bold blue] {message}")

    def print_success(self, message: str):
        console.print(f"  [bold green]✓[/bold green] {message}")

    def print_error(self, message: str):
        console.print(f"  [bold red]✗[/bold red] {message}")

    def print_incident(self, incident: dict):
        console.print()
        severity = incident.get("severity", "P3")
        sev_color = {"P1": "red", "P2": "dark_orange", "P3": "yellow", "P4": "green"}.get(severity, "yellow")

        console.print(
            Panel(
                f"[bold {sev_color}]{severity}[/bold {sev_color}] — {incident.get('title', 'Incident')}\n"
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
            table.add_row("Severity", impact.get("severity", "—"))
            table.add_row("Affected Services", ", ".join(impact.get("affected_services", [])))
            table.add_row("Blast Radius", impact.get("blast_radius", "—"))
            table.add_row("Est. Downtime", impact.get("estimated_downtime", "—"))
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
                    s.get("command", "—"),
                )
            console.print(st)

        prevention = incident.get("prevention", [])
        if prevention:
            console.print()
            console.print("[bold]Prevention:[/bold]")
            for p in prevention:
                console.print(f"  • {p}")

        console.print()
