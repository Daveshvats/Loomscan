"""ResultsView — shows scan results in the content area.

v5.14: Replaces the full-screen results screen with a content-area widget.
Shows a scrollable DataTable + summary stats.
"""
from __future__ import annotations

from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Static, DataTable, Label
from rich.text import Text


class ResultsView(Container):
    """Results view — scrollable findings table + summary."""

    CSS = """
    ResultsView {
        padding: 1 2;
    }

    ResultsView #results-header {
        color: $accent;
        text-style: bold;
        margin-bottom: 1;
    }

    ResultsView #results-summary {
        color: $text-muted;
        margin-bottom: 1;
    }

    ResultsView #results-table {
        height: 1fr;
        border: round $primary;
        padding: 1;
        background: #111111;
    }
    """

    def __init__(self, result):
        super().__init__()
        self._result = result

    def compose(self):
        yield Static("📊  Scan Results", id="results-header")

        findings = self._result.findings
        by_sev = {}
        for f in findings:
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            by_sev[sev] = by_sev.get(sev, 0) + 1

        summary = (f"Found {len(findings)} findings  •  "
                   f"Decision: {self._result.final_decision.value.upper()}  •  "
                   f"🔴 {by_sev.get('critical', 0)}  "
                   f"🟠 {by_sev.get('high', 0)}  "
                   f"🟡 {by_sev.get('medium', 0)}  "
                   f"🔵 {by_sev.get('low', 0)}")
        yield Static(summary, id="results-summary")

        table = DataTable(id="results-table")
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

        yield table
