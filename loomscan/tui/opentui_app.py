"""LoomScan TUI — built on OpenTUI (native Zig core).

v5.16: Complete rewrite using opentui (PyPI package) which is a Python port
of @opentui/core + @opentui/solid. This gives us the same rendering quality
as OpenCode/MiMoCode — native Zig core, reactive signals, full component
library.

Design:
  - ASCII block logo at top (LOOMSCAN in block chars)
  - Input bar at bottom (like MiMoCode/OpenCode)
  - Content area: shows ONLY progress (files/layer/status), NO findings
  - Status bar: engine, strictness, working directory
  - After scan: auto-generates HTML + SARIF, opens in browser

The TUI is minimal and clean — findings are viewed in the HTML report,
not cluttering the terminal.
"""
from __future__ import annotations

import asyncio
import os
import sys
import time
import threading
import subprocess
import platform
from pathlib import Path
from typing import Optional

from opentui import (
    render, Box, Text, Bold, Signal, component, use_keyboard, use_renderer,
    Input, ScrollBox, Column, Row, Spacer, For, Show, Conditional,
    BorderStyle, FlexDirection, AlignItems, JustifyContent,
)

from .logo import LOOMSCAN_LOGO


# ============================================================================
# App State (signals)
# ============================================================================

class AppState:
    """Reactive state shared across the app."""

    def __init__(self):
        self.working_dir = str(Path.cwd())
        self.engine = "auto"
        self.strictness = 5
        self.scan_result = None
        self.scan_config = None

        # Reactive signals for UI
        self.current_view = Signal("welcome", name="current_view")
        self.scan_stage = Signal("Idle", name="scan_stage")
        self.scan_progress = Signal(0, name="scan_progress")
        self.scan_files = Signal(0, name="scan_files")
        self.scan_findings = Signal(0, name="scan_findings")
        self.scan_running = Signal(False, name="scan_running")
        self.status_message = Signal("", name="status_message")
        self.input_value = Signal("", name="input_value")
        self.engine_label = Signal("Auto", name="engine_label")
        self.dir_label = Signal(self.working_dir, name="dir_label")


state = AppState()


# ============================================================================
# Logo Component
# ============================================================================

@component
def Logo():
    """Render the LOOMSCAN block-character logo."""
    return Column(
        *[Text(line, fg="#00aaff") for line in LOOMSCAN_LOGO],
        align_items=AlignItems.CENTER,
        gap=0,
    )


# ============================================================================
# Welcome View
# ============================================================================

@component
def WelcomeView():
    """Welcome screen — shows logo + quick commands."""
    return Column(
        Spacer(flex_grow=1),
        Logo(),
        Spacer(height=1),
        Text("Static + Test + Constraint Analysis", fg="#666666"),
        Spacer(height=2),
        Box(
            Column(
                Text("  Type a command to get started:", fg="#ffffff"),
                Spacer(height=1),
                Text("  scan        — Scan this repository", fg="#aaaaaa"),
                Text("  results     — Open last results in browser", fg="#aaaaaa"),
                Text("  doctor      — Check system health", fg="#aaaaaa"),
                Text("  settings    — View settings", fg="#aaaaaa"),
                Text("  /           — Command palette (all commands)", fg="#aaaaaa"),
                Spacer(height=1),
                Text("  Or press Ctrl+P for the command palette", fg="#555555"),
            ),
            border=True,
            border_color="#333333",
            padding=(1, 2),
            width=60,
        ),
        Spacer(flex_grow=1),
        align_items=AlignItems.CENTER,
        gap=0,
    )


# ============================================================================
# Scanning View — shows ONLY progress, no findings
# ============================================================================

@component
def ScanningView():
    """Scanning view — minimal progress display.

    Shows only:
      - Current stage (Layers, Taint, CPG, etc.)
      - Progress bar (0-100%)
      - Files analyzed count
      - Findings count (just a number, no details)

    No findings are displayed — they go to the HTML/SARIF report.
    """
    return Column(
        Spacer(flex_grow=1),
        Logo(),
        Spacer(height=2),
        # Progress panel
        Box(
            Column(
                Text(lambda: f"  {state.scan_stage()}", fg="#00aaff"),
                Spacer(height=1),
                # Progress bar
                Box(
                    Text(lambda: _progress_bar(state.scan_progress()),
                         fg="#00ff00"),
                    width=50,
                    border=False,
                    padding=0,
                ),
                Spacer(height=1),
                Row(
                    Text("  Files: ", fg="#666666"),
                    Text(lambda: str(state.scan_files()), fg="#ffffff"),
                    Spacer(width=2),
                    Text("Findings: ", fg="#666666"),
                    Text(lambda: str(state.scan_findings()), fg="#ffaa00"),
                    Spacer(flex_grow=1),
                    Text(lambda: f"{state.scan_progress()}%", fg="#00aaff"),
                ),
            ),
            border=True,
            border_color="#00aaff",
            padding=(1, 2),
            width=60,
        ),
        Spacer(height=1),
        Text("  Scan in progress... findings will open in browser when complete.",
             fg="#555555"),
        Spacer(flex_grow=1),
        align_items=AlignItems.CENTER,
        gap=0,
    )


def _progress_bar(pct: int) -> str:
    """Generate a text progress bar."""
    filled = int(pct / 100 * 40)
    return f"[{'█' * filled}{'░' * (40 - filled)}]"


# ============================================================================
# Results Complete View
# ============================================================================

@component
def ResultsView():
    """Shows when scan completes — link to open reports."""
    return Column(
        Spacer(flex_grow=1),
        Text("  ✓ Scan Complete!", fg="#00ff00"),
        Spacer(height=1),
        Text(lambda: f"  Found {state.scan_findings()} findings", fg="#ffaa00"),
        Spacer(height=2),
        Box(
            Column(
                Text("  Reports generated:", fg="#ffffff"),
                Spacer(height=1),
                Text("  📄 HTML report — opened in browser", fg="#00aaff"),
                Text("  📋 SARIF report — saved to .loomscan-reports/", fg="#00aaff"),
                Text("  📊 JSON report — saved to .loomscan-reports/", fg="#00aaff"),
                Spacer(height=1),
                Text("  Type 'open' to reopen the HTML report", fg="#666666"),
                Text("  Type 'scan' to scan again", fg="#666666"),
            ),
            border=True,
            border_color="#00ff00",
            padding=(1, 2),
            width=60,
        ),
        Spacer(flex_grow=1),
        align_items=AlignItems.CENTER,
        gap=0,
    )


# ============================================================================
# Settings View
# ============================================================================

@component
def SettingsView():
    """Settings view."""
    return Column(
        Spacer(flex_grow=1),
        Text("  ⚙️  Settings", fg="#00aaff"),
        Spacer(height=2),
        Box(
            Column(
                Text(lambda: f"  📁 Directory:  {state.dir_label()}", fg="#cccccc"),
                Text(lambda: f"  🚀 Engine:     {state.engine_label()}", fg="#cccccc"),
                Text(lambda: f"  📊 Strictness: {state.strictness}", fg="#cccccc"),
                Spacer(height=1),
                Text("  Commands:", fg="#ffffff"),
                Text("    cd <path>          — Change directory", fg="#888888"),
                Text("    engine <choice>    — auto/rust/semgrep/python", fg="#888888"),
                Text("    strictness <1-9>   — Set level", fg="#888888"),
                Text("    wizard             — Run config wizard", fg="#888888"),
            ),
            border=True,
            border_color="#333333",
            padding=(1, 2),
            width=60,
        ),
        Spacer(flex_grow=1),
        align_items=AlignItems.CENTER,
        gap=0,
    )


# ============================================================================
# Doctor View
# ============================================================================

@component
def DoctorView():
    """Doctor output view."""
    return Column(
        Spacer(flex_grow=1),
        Text("  🩺  System Health", fg="#00aaff"),
        Spacer(height=1),
        Box(
            Text("  Running doctor... output will appear in console.",
                 fg="#888888"),
            border=True,
            border_color="#333333",
            padding=(1, 2),
            width=60,
        ),
        Spacer(flex_grow=1),
        align_items=AlignItems.CENTER,
        gap=0,
    )


# ============================================================================
# Main App
# ============================================================================

@component
def App():
    """Main app — logo + dynamic content + input bar + status bar."""

    # Dynamic content based on current view
    def content():
        view = state.current_view()
        if view == "welcome":
            return WelcomeView()
        elif view == "scanning":
            return ScanningView()
        elif view == "results":
            return ResultsView()
        elif view == "settings":
            return SettingsView()
        elif view == "doctor":
            return DoctorView()
        return WelcomeView()

    return Column(
        # Main content area (flex_grow=1)
        Box(
            content(),
            flex_grow=1,
            padding=(1, 2),
        ),
        # Input bar at bottom
        Box(
            Row(
                Text("▸ ", fg="#00aaff"),
                _InputBar(),
                flex_grow=1,
            ),
            border=True,
            border_color="#00aaff",
            padding=(0, 1),
            height=3,
        ),
        # Status bar
        Row(
            Text(" 🚀 ", fg="#00aaff"),
            Text(lambda: state.engine_label(), fg="#00aaff"),
            Text("  ·  📊 Lvl ", fg="#666666"),
            Text(lambda: str(state.strictness), fg="#ffffff"),
            Text("  ·  📁 ", fg="#666666"),
            Text(lambda: state.dir_label(), fg="#888888"),
            Spacer(flex_grow=1),
            Text(" v5.16  ", fg="#444444"),
        ),
        height=1,
    )


@component
def _InputBar():
    """Input bar component."""
    return Input(
        placeholder="Type a command or / for palette  (e.g. scan, results, doctor)",
        on_submit=_handle_input,
        flex_grow=1,
    )


def _handle_input(value: str):
    """Handle user input from the input bar."""
    text = value.strip()
    if not text:
        return

    parts = text.split(None, 1)
    cmd = parts[0].lower().lstrip("/")
    arg = parts[1] if len(parts) > 1 else ""

    _route_command(cmd, arg)


def _route_command(cmd: str, arg: str):
    """Route a command to the appropriate handler."""

    # === Scan ===
    if cmd in ("scan", "run"):
        repo = arg if arg else state.working_dir
        _start_scan(repo)
    elif cmd == "scan_diff":
        _start_scan(state.working_dir, full=False)

    # === Results ===
    elif cmd == "results":
        _open_results()
    elif cmd == "open":
        _open_results()

    # === Config ===
    elif cmd == "settings":
        state.current_view.set("settings")
    elif cmd == "cd":
        _change_dir(arg)
    elif cmd == "engine":
        _set_engine(arg)
    elif cmd in ("strictness", "level"):
        _set_strictness(arg)
    elif cmd == "wizard":
        _run_wizard()

    # === System ===
    elif cmd == "doctor":
        _run_doctor()
    elif cmd == "help":
        state.current_view.set("welcome")

    elif cmd in ("quit", "exit", "q"):
        r = use_renderer()
        if r:
            r.stop()

    else:
        state.status_message.set(f"Unknown: {cmd}. Type 'help' for commands.")


def _start_scan(repo_path: str, full: bool = True):
    """Start a scan in a background thread."""
    state.scan_running.set(True)
    state.scan_progress.set(0)
    state.scan_files.set(0)
    state.scan_findings.set(0)
    state.scan_stage.set("Initializing...")
    state.current_view.set("scanning")

    def _scan_thread():
        try:
            from ..config import STCAConfig, find_config
            from ..orchestrator import Orchestrator
            from ..tui.progress import ScanProgress

            repo = Path(repo_path)
            if not repo.exists():
                state.scan_stage.set(f"Error: {repo} not found")
                return

            # Engine selection
            if state.engine == "rust":
                os.environ["LOOMSCAN_ENGINE"] = "rust"
            elif state.engine == "semgrep":
                os.environ["LOOMSCAN_ENGINE"] = "semgrep"
            elif state.engine == "python":
                os.environ["LOOMSCAN_ENGINE"] = "python"
            else:
                os.environ.pop("LOOMSCAN_ENGINE", None)

            cfg = STCAConfig.from_file(find_config(repo))
            progress = ScanProgress(total_stages=7, enabled=False)
            orch = Orchestrator(repo, cfg,
                               strictness=state.strictness,
                               progress=progress)

            state.scan_stage.set("Loading configuration...")

            # Polling thread for progress
            stop_polling = threading.Event()

            def _poll():
                last = 0
                while not stop_polling.is_set():
                    if progress.completed_stages > last:
                        last = progress.completed_stages
                        pct = 15 + (last / 7) * 70
                        state.scan_progress.set(int(pct))
                        names = [s.name for s in progress.stages]
                        if names:
                            state.scan_stage.set(names[-1])
                        total_findings = sum(s.findings_count for s in progress.stages)
                        state.scan_findings.set(total_findings)
                    stop_polling.wait(0.1)

            poll = threading.Thread(target=_poll, daemon=True)
            poll.start()

            state.scan_stage.set("Scanning...")
            if full:
                result = orch.run_full()
            else:
                result = orch.run()

            stop_polling.set()

            state.scan_progress.set(100)
            state.scan_stage.set("Generating reports...")
            state.scan_findings.set(len(result.findings))

            # Auto-generate reports
            _generate_reports(result, repo)

            state.scan_result = result
            state.scan_running.set(False)
            state.scan_stage.set("Complete!")
            state.current_view.set("results")

        except Exception as e:
            state.scan_stage.set(f"Error: {e}")
            state.scan_running.set(False)

    t = threading.Thread(target=_scan_thread, daemon=True)
    t.start()


def _generate_reports(result, repo: Path):
    """Generate HTML + SARIF + JSON reports and open HTML in browser."""
    try:
        from ..report.sarif import save_sarif
        from ..report.html import save_html

        report_dir = repo / ".loomscan-reports"
        report_dir.mkdir(parents=True, exist_ok=True)

        # SARIF
        sarif_path = report_dir / "result.sarif"
        save_sarif(result, repo, sarif_path)

        # HTML
        html_path = report_dir / "report.html"
        save_html(result, repo, html_path)

        # JSON
        json_path = report_dir / "result.json"
        result.to_json(json_path)

        # Open HTML in browser (platform-specific)
        _open_in_browser(html_path)

    except Exception as e:
        state.status_message.set(f"Report error: {e}")


def _open_in_browser(path: Path):
    """Open a file in the default browser (platform-specific)."""
    abs_path = str(path.resolve())
    try:
        system = platform.system()
        if system == "Darwin":
            subprocess.Popen(["open", abs_path])
        elif system == "Linux":
            subprocess.Popen(["xdg-open", abs_path])
        elif system == "Windows":
            subprocess.Popen(["cmd", "/c", "start", "", abs_path], shell=False)
    except Exception:
        pass


def _open_results():
    """Open the HTML report in browser."""
    repo = Path(state.working_dir)
    html_path = repo / ".loomscan-reports" / "report.html"
    if html_path.exists():
        _open_in_browser(html_path)
    else:
        state.status_message.set("No results yet. Run 'scan' first.")


def _change_dir(path: str):
    """Change working directory."""
    if not path:
        return
    new_path = Path(path).expanduser().resolve()
    if new_path.exists() and new_path.is_dir():
        state.working_dir = str(new_path)
        state.dir_label.set(str(new_path))
    else:
        state.status_message.set(f"Directory not found: {path}")


def _set_engine(choice: str):
    """Set the YAML engine."""
    if choice in ("auto", "rust", "semgrep", "python"):
        state.engine = choice
        labels = {"auto": "Auto", "rust": "Rust core", "semgrep": "Semgrep",
                  "python": "Python re"}
        state.engine_label.set(labels[choice])
    else:
        state.status_message.set("Engine must be: auto, rust, semgrep, or python")


def _set_strictness(arg: str):
    """Set strictness level."""
    try:
        level = max(1, min(9, int(arg)))
        state.strictness = level
    except ValueError:
        state.status_message.set("Strictness must be 1-9")


def _run_doctor():
    """Run doctor command."""
    state.current_view.set("doctor")
    def _doctor_thread():
        try:
            result = subprocess.run(
                [sys.executable, "-m", "loomscan.cli", "doctor"],
                capture_output=True, text=True, timeout=30
            )
            # Doctor output goes to console (TUI stays clean)
            print(result.stdout)
        except Exception as e:
            state.status_message.set(f"Doctor error: {e}")
        state.current_view.set("welcome")
    threading.Thread(target=_doctor_thread, daemon=True).start()


def _run_wizard():
    """Run config wizard (simplified — creates default config)."""
    try:
        from ..config import STCAConfig
        cfg = STCAConfig.default()
        cfg_path = Path(state.working_dir) / ".loomscan.yaml"
        cfg.save(cfg_path)
        state.status_message.set(f"Config saved to {cfg_path}")
    except Exception as e:
        state.status_message.set(f"Wizard error: {e}")


# ============================================================================
# Keyboard Handler
# ============================================================================

def _on_key(event):
    """Global keyboard handler."""
    if event.name == "q" and state.current_view() != "scanning":
        # Only quit if not scanning
        if not state.scan_running():
            r = use_renderer()
            if r:
                r.stop()
    elif event.name == "escape":
        if state.current_view() == "scanning":
            # Don't escape during scan
            pass
        else:
            state.current_view.set("welcome")


# ============================================================================
# Launch
# ============================================================================

def launch_tui() -> int:
    """Launch the LoomScan TUI app."""
    try:
        use_keyboard(_on_key)
        asyncio.run(render(App))
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        print(f"LoomScan TUI error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return 1
