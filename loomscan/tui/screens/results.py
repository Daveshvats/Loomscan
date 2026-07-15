"""Results screen — beautiful findings table + stats sidebar.

v5.13: Redesigned with:
- Responsive layout (sidebar + main table)
- Stats sidebar with severity breakdown
- Scrollable DataTable with color-coded severity
- Export buttons with icons
- Summary panel at top
"""
from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical, Center, Middle
from textual.screen import Screen
from textual.widgets import (
    Static, Button, DataTable, Label
)
from textual.binding import Binding
from rich.text import Text


class ResultsScreen(Screen):
    """Results screen — scrollable findings table + export options."""

    CSS = """
    ResultsScreen {
        align: center middle;
    }

    ResultsScreen #main-box {
        width: 1fr;
        max-width: 110;
        min-width: 50;
        height: 1fr;
        max-height: 90%;
        padding: 1 2;
    }

    ResultsScreen #header {
        text-align: center;
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }

    ResultsScreen #summary-panel {
        border: round $accent;
        padding: 1;
        margin-bottom: 1;
        background: $panel;
        text-align: center;
    }

    ResultsScreen #body-row {
        height: 1fr;
    }

    ResultsScreen #stats-panel {
        width: 25;
        height: 100%;
        border: round $primary;
        padding: 1;
        background: $panel;
    }

    ResultsScreen .stat-title {
        color: $accent;
        text-style: bold;
        margin-bottom: 1;
    }

    ResultsScreen .stat-row {
        margin-bottom: 0;
    }

    ResultsScreen .stat-label {
        color: $text-muted;
    }

    ResultsScreen .stat-value {
        color: $text;
        text-style: bold;
    }

    ResultsScreen #table-panel {
        width: 1fr;
        height: 100%;
        border: round $primary;
        padding: 1;
        background: $boost;
    }

    ResultsScreen #table-title {
        color: $accent;
        text-style: bold;
        margin-bottom: 0;
    }

    ResultsScreen #findings-table {
        height: 1fr;
    }

    ResultsScreen #buttons {
        height: 3;
        align: center middle;
        margin-top: 1;
    }

    ResultsScreen .export-btn {
        margin-right: 1;
    }

    ResultsScreen #status {
        color: $success;
        text-align: center;
        margin-top: 1;
    }
    """

    BINDINGS = [
        Binding("escape", "back", "Back"),
        Binding("e", "export_sarif", "SARIF"),
        Binding("j", "export_json", "JSON"),
        Binding("q", "quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        with Center():
            with Middle():
                with Container(id="main-box"):
                    yield Static("📊  Scan Results", id="header")

                    with Container(id="summary-panel"):
                        yield Static("", id="summary")

                    with Horizontal(id="body-row"):
                        with Container(id="stats-panel"):
                            yield Static("📈  Statistics", classes="stat-title")
                            yield Static("Critical: 0", id="stat-critical",
                                        classes="stat-row")
                            yield Static("High: 0", id="stat-high",
                                        classes="stat-row")
                            yield Static("Medium: 0", id="stat-medium",
                                        classes="stat-row")
                            yield Static("Low: 0", id="stat-low",
                                        classes="stat-row")
                            yield Static("", id="stat-divider")
                            yield Static("Total: 0", id="stat-total",
                                        classes="stat-row")
                            yield Static("", id="stat-spacer")
                            yield Static("Decision: PASS", id="stat-decision",
                                        classes="stat-row")

                        with Container(id="table-panel"):
                            yield Static("🔍  Findings", id="table-title")
                            yield DataTable(id="findings-table")

                    with Horizontal(id="buttons"):
                        yield Button("📋  Export SARIF", id="btn-sarif",
                                    variant="primary", classes="export-btn")
                        yield Button("📄  Export JSON", id="btn-json",
                                    classes="export-btn")
                        yield Button("🔄  New Scan", id="btn-new",
                                    classes="export-btn")
                        yield Button("🏠  Home", id="btn-home",
                                    classes="export-btn")
                    yield Static("", id="status")

    def on_mount(self) -> None:
        result = getattr(self.app, "scan_result", None)
        if not result:
            self.query_one("#summary", Static).update(
                "No scan results. Run a scan first."
            )
            return

        findings = result.findings
        by_sev = {}
        for f in findings:
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            by_sev[sev] = by_sev.get(sev, 0) + 1

        # Summary
        summary = (f"Found {len(findings)} findings  •  "
                   f"Decision: {result.final_decision.value.upper()}")
        self.query_one("#summary", Static).update(summary)

        # Stats sidebar
        self.query_one("#stat-critical", Static).update(
            f"🔴 Critical: {by_sev.get('critical', 0)}")
        self.query_one("#stat-high", Static).update(
            f"🟠 High: {by_sev.get('high', 0)}")
        self.query_one("#stat-medium", Static).update(
            f"🟡 Medium: {by_sev.get('medium', 0)}")
        self.query_one("#stat-low", Static).update(
            f"🔵 Low: {by_sev.get('low', 0)}")
        self.query_one("#stat-total", Static).update(
            f"📊 Total: {len(findings)}")
        self.query_one("#stat-decision", Static).update(
            f"⚖️ Decision: {result.final_decision.value.upper()}")

        # Build table
        table = self.query_one("#findings-table", DataTable)
        table.add_columns("#", "Sev", "Rule ID", "File", "Line", "Message")
        table.cursor_type = "row"

        sev_colors = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }

        for i, f in enumerate(findings, 1):
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            sev_style = sev_colors.get(sev, "white")
            table.add_row(
                str(i),
                Text(sev.upper()[:3], style=sev_style),
                f.rule_id,
                f.file,
                str(f.start_line),
                f.message[:80],
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-sarif":
            self._export_sarif()
        elif event.button.id == "btn-json":
            self._export_json()
        elif event.button.id == "btn-new":
            self.app.switch_mode("config")
        elif event.button.id == "btn-home":
            self.app.switch_mode("welcome")

    def _export_sarif(self) -> None:
        result = getattr(self.app, "scan_result", None)
        if not result:
            return
        try:
            from ..report.sarif import save_sarif
            repo_root = Path(self.app.scan_config["repo"])
            sarif_path = repo_root / "loomscan-report.sarif"
            save_sarif(result, repo_root, sarif_path)
            self.query_one("#status", Static).update(
                f"✓ SARIF exported to {sarif_path}"
            )
        except Exception as e:
            self.query_one("#status", Static).update(f"✗ Export failed: {e}")

    def _export_json(self) -> None:
        result = getattr(self.app, "scan_result", None)
        if not result:
            return
        try:
            import json
            repo_root = Path(self.app.scan_config["repo"])
            json_path = repo_root / "loomscan-report.json"
            json_path.write_text(json.dumps(result.to_dict(), indent=2))
            self.query_one("#status", Static).update(
                f"✓ JSON exported to {json_path}"
            )
        except Exception as e:
            self.query_one("#status", Static).update(f"✗ Export failed: {e}")

    def action_export_sarif(self) -> None:
        self._export_sarif()

    def action_export_json(self) -> None:
        self._export_json()

    def action_back(self) -> None:
        self.app.switch_mode("welcome")

    def action_quit(self) -> None:
        self.app.exit()
