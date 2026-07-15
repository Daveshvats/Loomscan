"""Rich-based CLI display for LoomScan scans.

v5.17: Replaces the TUI with a clean, responsive Rich CLI display that shows:
  - ASCII art logo (LOOMSCAN) at top
  - Two-column layout: main panel (progress) + sidebar (project info)
  - Real-time findings count (critical/high/medium/low)
  - Stage progress (Layer X/7)
  - Files scanned / excluded
  - Active modules
  - Elapsed time
  - After scan: HTML + SARIF file locations

Uses Rich's Live display for smooth real-time updates.
No TUI, no mascot — just beautiful CLI output.
"""
from __future__ import annotations

import os
import sys
import time
import threading
from pathlib import Path
from typing import Optional, Dict, List
from datetime import timedelta

from rich.console import Console, Group
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.layout import Layout
from rich.align import Align
from rich import box
from rich.rule import Rule

try:
    import pyfiglet
    _HAS_FIGLET = True
except ImportError:
    _HAS_FIGLET = False


def _get_logo() -> str:
    """Get the LOOMSCAN ASCII art logo."""
    if _HAS_FIGLET:
        try:
            return pyfiglet.figlet_format("LOOMSCAN", font="ansi_shadow")
        except Exception:
            pass
    # Fallback: simple text
    return "  ███╗      ███╗ ██████╗ ██╗   ██╗ ██████╗ ...\n  L O O M S C A N"


def _get_logo_text(version: str = "") -> Text:
    """Get the logo as a styled Rich Text with gradient colors."""
    logo = _get_logo()
    # Gradient colors: orange → red → purple → blue
    colors = ["#ff6600", "#ff4444", "#cc44cc", "#6644cc", "#4466ff"]
    lines = logo.rstrip().split("\n")
    text = Text()
    for i, line in enumerate(lines):
        color = colors[i % len(colors)]
        text.append(line + "\n", style=color)
    if version:
        text.append(f"  v{version}", style="bold #4466ff")
    return text


class CLIDisplay:
    """Rich-based CLI display for scan progress.

    Usage:
        display = CLIDisplay(console, repo_path, version="5.17.0")
        display.start()
        # ... during scan, update state:
        display.update_stage("Data Flow Analysis", stage_num=3, total_stages=7)
        display.update_files(scanned=526, total=1248, current_file="src/auth.py")
        display.update_findings(critical=10, high=20, medium=20, low=30)
        display.update_modules(["secrets", "taint", "cpg", ...])
        display.update_excludes(excluded_files=146, excluded_folders=34)
        # ... when done:
        display.finish(html_path=Path("..."), sarif_path=Path("..."))
    """

    def __init__(self, console: Console, repo_path: str, version: str = "",
                 command: str = "", engine: str = "auto", excludes: List[str] = None):
        self.console = console
        self.repo_path = repo_path
        self.version = version
        self.command = command or "loomscan scan"
        self.engine = engine
        self.excludes = excludes or []

        # State
        self.start_time = time.perf_counter()
        self.current_stage = "Initializing..."
        self.stage_num = 0
        self.total_stages = 7
        self.progress_pct = 0
        self.files_scanned = 0
        self.files_total = 0
        self.current_file = ""
        self.excluded_files = 0
        self.excluded_folders = 0
        self.findings = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        self.active_modules: List[str] = []
        self.total_modules = 18
        self.scan_complete = False
        self.html_path: Optional[Path] = None
        self.sarif_path: Optional[Path] = None
        self.json_path: Optional[Path] = None

        # Live display
        self._live: Optional[Live] = None
        self._stop_event = threading.Event()
        self._poll_thread: Optional[threading.Thread] = None

    def start(self):
        """Start the live display with auto-refresh for elapsed time."""
        self._live = Live(
            self._render(),
            console=self.console,
            refresh_per_second=2,  # v5.20: Refresh 2x/sec for live elapsed time
            transient=False,
        )
        self._live.start()

        # v5.20: Background timer to force refresh every second
        # (Live refresh_per_second handles this, but we also need
        # to update the rendered content)
        self._refresh_thread = threading.Thread(target=self._auto_refresh, daemon=True)
        self._refresh_thread.start()

    def _auto_refresh(self):
        """v5.20: Auto-refresh the display every second for elapsed time."""
        while self._live and not self.scan_complete:
            self._refresh()
            time.sleep(1.0)

    def stop(self):
        """Stop the live display."""
        self.scan_complete = True  # Stop auto-refresh
        if self._live:
            self._live.stop()
            self._live = None

    def update_stage(self, stage: str, stage_num: int = 0, total_stages: int = 7):
        """Update the current scan stage."""
        self.current_stage = stage
        if stage_num > 0:
            self.stage_num = stage_num
        self.total_stages = total_stages
        if stage_num > 0:
            self.progress_pct = int((stage_num / total_stages) * 100)
        self._refresh()

    def update_files(self, scanned: int, total: int, current_file: str = ""):
        """Update file scanning progress."""
        self.files_scanned = scanned
        self.files_total = total
        if current_file:
            self.current_file = current_file
        self._refresh()

    def update_findings(self, critical: int = 0, high: int = 0,
                        medium: int = 0, low: int = 0, info: int = 0):
        """Update findings count."""
        self.findings = {"critical": critical, "high": high,
                        "medium": medium, "low": low, "info": info}
        self._refresh()

    def update_modules(self, modules: List[str], total: int = 18):
        """Update active modules list."""
        self.active_modules = modules
        self.total_modules = total
        self._refresh()

    def update_excludes(self, excluded_files: int = 0, excluded_folders: int = 0):
        """Update excluded files/folders count."""
        self.excluded_files = excluded_files
        self.excluded_folders = excluded_folders
        self._refresh()

    def set_progress(self, pct: int):
        """Set progress percentage directly."""
        self.progress_pct = max(0, min(100, pct))
        self._refresh()

    def finish(self, html_path: Optional[Path] = None,
               sarif_path: Optional[Path] = None,
               json_path: Optional[Path] = None):
        """Mark scan as complete and show final output."""
        self.scan_complete = True
        self.progress_pct = 100
        self.html_path = html_path
        self.sarif_path = sarif_path
        self.json_path = json_path
        self._refresh()
        self.stop()

        # Print final summary (after live display stops)
        self._print_final_summary()

    def _refresh(self):
        """Refresh the live display."""
        if self._live:
            self._live.update(self._render())

    def _render(self):
        """Render the complete display."""
        elapsed = time.perf_counter() - self.start_time
        elapsed_str = str(timedelta(seconds=int(elapsed)))

        # === Header (logo + version) ===
        header = Panel(
            Align.center(_get_logo_text(self.version)),
            border_style="bright_blue",
            padding=(0, 2),
        )

        # === Main Panel (left) — scan progress ===
        main_table = Table(show_header=False, box=None, padding=(0, 1))
        main_table.add_column("label", style="dim", width=20)
        main_table.add_column("value", style="white")

        # Command
        main_table.add_row("Command", f"[bold cyan]{self.command}[/bold cyan]")

        # Status
        if self.scan_complete:
            status_text = "[bold green]✓ Scan complete![/bold green]"
        else:
            spinner = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"[int(time.time() * 4) % 10]
            status_text = f"[bold yellow]{spinner} Scanning in progress...[/bold yellow]"
        main_table.add_row("Status", status_text)

        # Stage
        if self.stage_num > 0:
            main_table.add_row("Stage",
                f"[bold]{self.stage_num}[/bold] / {self.total_stages}  "
                f"[dim]{self.current_stage}[/dim]")
        else:
            main_table.add_row("Stage", f"[dim]{self.current_stage}[/dim]")

        # Progress bar
        filled = int(self.progress_pct / 100 * 30)
        bar = f"[green]{'█' * filled}[/green][dim]{'░' * (30 - filled)}[/dim]"
        main_table.add_row("Progress", f"{bar}  {self.progress_pct}%")

        # Files
        if self.files_total > 0:
            main_table.add_row("Files",
                f"[bold]{self.files_scanned}[/bold] / {self.files_total} files")
        else:
            main_table.add_row("Files", f"[bold]{self.files_scanned}[/bold] files")

        # Current file
        if self.current_file and not self.scan_complete:
            # Truncate long paths
            f = self.current_file
            if len(f) > 50:
                f = "..." + f[-47:]
            main_table.add_row("Current file", f"[dim]{f}[/dim]")

        # Elapsed time
        main_table.add_row("Elapsed", f"[bold]{elapsed_str}[/bold]")

        # Findings summary
        main_table.add_row("", "")
        main_table.add_row("[bold]Findings[/bold]", "")
        f = self.findings
        main_table.add_row("  Critical", f"[bold red]🔴 {f['critical']}[/bold red]")
        main_table.add_row("  High", f"[bold orange]🟠 {f['high']}[/bold orange]")
        main_table.add_row("  Medium", f"[bold yellow]🟡 {f['medium']}[/bold yellow]")
        main_table.add_row("  Low", f"[bold blue]🔵 {f['low']}[/bold blue]")
        total = sum(f.values())
        main_table.add_row("  Total", f"[bold white]📊 {total}[/bold white]")

        main_panel = Panel(
            main_table,
            title="[bold blue]Scan Progress[/bold blue]",
            border_style="blue",
            padding=(1, 1),
        )

        # === Sidebar (right) — project info ===
        side_table = Table(show_header=False, box=None, padding=(0, 1))
        side_table.add_column("label", style="dim", width=18)
        side_table.add_column("value", style="white")

        # Project info
        side_table.add_row("[bold]Project[/bold]", "")
        repo_name = Path(self.repo_path).name
        side_table.add_row("  Folder", f"[bold]{repo_name}[/bold]")
        side_table.add_row("  Path", f"[dim]{self.repo_path}[/dim]")
        if self.files_total > 0:
            side_table.add_row("  Total files", f"[bold]{self.files_total}[/bold]")
        side_table.add_row("  Excluded files", f"[dim]{self.excluded_files}[/dim]")
        side_table.add_row("  Excluded folders", f"[dim]{self.excluded_folders}[/dim]")

        # v5.18: Engine selection
        engine_labels = {"auto": "Auto-detect", "rust": "Rust core",
                        "semgrep": "Semgrep", "python": "Python re"}
        side_table.add_row("  Engine", f"[bold cyan]{engine_labels.get(self.engine, self.engine)}[/bold cyan]")

        # v5.18: Custom excludes (from --exclude flag)
        if self.excludes:
            exc_str = ", ".join(self.excludes[:5])
            if len(self.excludes) > 5:
                exc_str += f", +{len(self.excludes) - 5} more"
            side_table.add_row("  CLI excludes", f"[dim]{exc_str}[/dim]")

        # Active modules
        side_table.add_row("", "")
        side_table.add_row("[bold]Modules[/bold]",
            f"[bold]{len(self.active_modules)}[/bold] / {self.total_modules} active")
        if self.active_modules:
            # Show modules in a compact list
            modules_str = ", ".join(self.active_modules[:8])
            if len(self.active_modules) > 8:
                modules_str += f", +{len(self.active_modules) - 8} more"
            side_table.add_row("  Active", f"[dim]{modules_str}[/dim]")

        # Pipeline stages
        side_table.add_row("", "")
        side_table.add_row("[bold]Pipeline[/bold]", "")
        stages = ["L0 Fast", "L1 Property", "L2 Coverage", "L3 Invariants",
                  "L4 Fuzz", "L5 Policy", "L6 Symbolic", "L7 Simulation"]
        for i, stage in enumerate(stages):  # v5.19: Start at 0 (L0, L1, ...)
            stage_num = i  # 0-based for display
            if i < self.stage_num - 1:  # stage_num is 1-based from orchestrator
                icon = "✓"
                style = "green"
            elif i == self.stage_num - 1 and not self.scan_complete:
                icon = "▶"
                style = "yellow"
            elif self.scan_complete:
                icon = "✓"
                style = "green"
            else:
                icon = "○"
                style = "dim"
            side_table.add_row(f"  {icon} L{stage_num}", f"[{style}]{stage}[/{style}]")

        side_panel = Panel(
            side_table,
            title="[bold green]Project Info[/bold green]",
            border_style="green",
            padding=(1, 1),
        )

        # === Two-column layout ===
        columns = Table.grid(expand=True, padding=(0, 1))
        columns.add_column(ratio=3)  # Main panel (wider)
        columns.add_column(ratio=2)  # Sidebar
        columns.add_row(main_panel, side_panel)

        # === Complete output ===
        if self.scan_complete and (self.html_path or self.sarif_path):
            output_table = Table(show_header=False, box=None, padding=(0, 1))
            output_table.add_column("label", style="dim", width=20)
            output_table.add_column("value", style="green")
            output_table.add_row("HTML Report",
                f"[bold green]📄 {self.html_path}[/bold green]" if self.html_path else "[dim]N/A[/dim]")
            output_table.add_row("SARIF Report",
                f"[bold cyan]📋 {self.sarif_path}[/bold cyan]" if self.sarif_path else "[dim]N/A[/dim]")
            output_table.add_row("JSON Report",
                f"[bold yellow]📊 {self.json_path}[/bold yellow]" if self.json_path else "[dim]N/A[/dim]")
            output_panel = Panel(
                output_table,
                title="[bold green]Generated Reports[/bold green]",
                border_style="green",
                padding=(1, 1),
            )
            return Group(header, columns, output_panel)
        else:
            return Group(header, columns)

    def _print_final_summary(self):
        """Print final summary after live display stops."""
        elapsed = time.perf_counter() - self.start_time
        elapsed_str = str(timedelta(seconds=int(elapsed)))
        f = self.findings
        total = sum(f.values())

        self.console.print()
        self.console.print(Rule("[bold green]Scan Complete[/bold green]",
                               style="green"))
        self.console.print()

        # Summary table
        summary = Table(title="Scan Summary", box=box.ROUNDED, show_lines=True)
        summary.add_column("Metric", style="cyan", width=25)
        summary.add_column("Value", style="white")
        summary.add_row("Elapsed time", f"[bold]{elapsed_str}[/bold]")
        summary.add_row("Files scanned", f"[bold]{self.files_scanned}[/bold]")
        summary.add_row("Files excluded", f"[dim]{self.excluded_files}[/dim]")
        summary.add_row("Modules active",
                        f"[bold]{len(self.active_modules)}[/bold] / {self.total_modules}")
        summary.add_row("Total findings", f"[bold]{total}[/bold]")
        summary.add_row("  Critical", f"[bold red]🔴 {f['critical']}[/bold red]")
        summary.add_row("  High", f"[bold orange]🟠 {f['high']}[/bold orange]")
        summary.add_row("  Medium", f"[bold yellow]🟡 {f['medium']}[/bold yellow]")
        summary.add_row("  Low", f"[bold blue]🔵 {f['low']}[/bold blue]")
        self.console.print(summary)

        # Report locations
        if self.html_path or self.sarif_path:
            self.console.print()
            reports = Table(title="Reports Generated", box=box.ROUNDED)
            reports.add_column("Type", style="cyan", width=15)
            reports.add_column("Location", style="green")
            if self.html_path:
                reports.add_row("📄 HTML", str(self.html_path))
            if self.sarif_path:
                reports.add_row("📋 SARIF", str(self.sarif_path))
            if self.json_path:
                reports.add_row("📊 JSON", str(self.json_path))
            self.console.print(reports)

        self.console.print()
        self.console.print("[dim]View the HTML report in your browser for detailed findings.[/dim]")
        self.console.print()
