"""Scanning screen — live progress + animated mascot + scrollable log.

v5.13: Redesigned with:
- Responsive 3-panel layout (mascot | progress | log)
- Bordered panels with titles
- Mascot in a framed panel
- Progress bar with percentage
- Scrollable log panel (older logs don't disappear)
- Cancel button
"""
from __future__ import annotations

import os
import time
import threading
from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical, Center, Middle
from textual.screen import Screen
from textual.widgets import Static, Button, ProgressBar, RichLog, Label
from textual.binding import Binding
from textual.reactive import reactive
from textual.worker import Worker

from ..mascot_widget import MascotWidget


class ScanningScreen(Screen):
    """Scanning screen — live progress + mascot + log."""

    CSS = """
    ScanningScreen {
        align: center middle;
    }

    ScanningScreen #main-box {
        width: 1fr;
        max-width: 100;
        min-width: 50;
        height: 1fr;
        max-height: 90%;
        padding: 1 2;
    }

    ScanningScreen #header {
        text-align: center;
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }

    ScanningScreen #top-row {
        height: 20;
        margin-bottom: 1;
    }

    ScanningScreen #mascot-panel {
        width: 30;
        height: 100%;
        border: round $primary;
        padding: 1;
        align: center middle;
        background: $panel;
    }

    ScanningScreen #progress-panel {
        width: 1fr;
        height: 100%;
        border: round $accent;
        padding: 1;
        background: $panel;
    }

    ScanningScreen #stage-label {
        color: $accent;
        text-style: bold;
        margin-bottom: 1;
    }

    ScanningScreen #scan-progress {
        margin-bottom: 1;
    }

    ScanningScreen #findings-label {
        color: $text-muted;
    }

    ScanningScreen #log-panel {
        height: 1fr;
        border: round $primary;
        padding: 1;
        background: $boost;
    }

    ScanningScreen #log-title {
        color: $accent;
        text-style: bold;
        margin-bottom: 0;
    }

    ScanningScreen #scan-log {
        height: 1fr;
    }

    ScanningScreen #buttons {
        height: 3;
        align: center middle;
        margin-top: 1;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("ctrl+c", "cancel", "Cancel"),
    ]

    findings_count: reactive[int] = reactive(0)
    current_stage: reactive[str] = reactive("Initializing...")

    def compose(self) -> ComposeResult:
        with Center():
            with Middle():
                with Container(id="main-box"):
                    yield Static("🔍  Scanning...", id="header")

                    with Horizontal(id="top-row"):
                        with Container(id="mascot-panel"):
                            yield MascotWidget(id="mascot")

                        with Vertical(id="progress-panel"):
                            yield Static("Initializing...", id="stage-label")
                            yield ProgressBar(total=100, id="scan-progress",
                                            show_percentage=True)
                            yield Static("0 findings", id="findings-label")

                    with Container(id="log-panel"):
                        yield Static("📋  Scan Log", id="log-title")
                        yield RichLog(id="scan-log", highlight=True, markup=True)

                    with Horizontal(id="buttons"):
                        yield Button("✕  Cancel Scan", id="cancel-btn",
                                    variant="error")

    def on_mount(self) -> None:
        config = getattr(self.app, "scan_config", None)
        if not config:
            self.query_one("#scan-log", RichLog).write(
                "[red]Error: No scan configuration found[/red]"
            )
            return
        self._scan_worker = self.run_worker(
            self._run_scan,
            thread=True,
            exclusive=True,
            group="scan",
        )

    def _run_scan(self) -> None:
        """Run the scan in a background thread.

        v5.13 FIX: Removed the `worker` parameter — Textual's run_worker()
        calls the function without arguments.
        """
        try:
            config = self.app.scan_config
            repo_path = Path(config["repo"])

            # v5.12: Engine selection
            engine_choice = config.get("engine", "auto")
            if engine_choice == "rust":
                os.environ["LOOMSCAN_ENGINE"] = "rust"
                self.app.call_from_thread(self._log,
                    "[cyan]🚀 Engine: Rust core (user-selected)[/cyan]")
            elif engine_choice == "semgrep":
                os.environ["LOOMSCAN_ENGINE"] = "semgrep"
                self.app.call_from_thread(self._log,
                    "[cyan]🔍 Engine: Semgrep (user-selected)[/cyan]")
            elif engine_choice == "python":
                os.environ["LOOMSCAN_ENGINE"] = "python"
                self.app.call_from_thread(self._log,
                    "[cyan]🐍 Engine: Python re (user-selected)[/cyan]")
            else:
                os.environ.pop("LOOMSCAN_ENGINE", None)
                self.app.call_from_thread(self._log,
                    "[cyan]⚙️ Engine: Auto-detect[/cyan]")

            from ..config import STCAConfig, find_config
            from ..orchestrator import Orchestrator
            from ..tui.progress import ScanProgress

            self.app.call_from_thread(self._update_stage,
                                       "Loading configuration...", 5)
            self.app.call_from_thread(self._log, f"📁 Scanning: {repo_path}")

            cfg = STCAConfig.from_file(find_config(repo_path))

            self.app.call_from_thread(self._update_stage,
                                       "Running scan layers...", 15)
            self.app.call_from_thread(self._log, "✓ Configuration loaded")

            progress = ScanProgress(total_stages=7, enabled=False)
            orch = Orchestrator(repo_path, cfg,
                               strictness=config.get("strictness", 5),
                               progress=progress)

            self.app.call_from_thread(self._log, "▶ Starting scan...")

            # Progress polling thread
            stop_polling = threading.Event()

            def _poll_progress():
                last_completed = 0
                while not stop_polling.is_set():
                    if progress.completed_stages > last_completed:
                        last_completed = progress.completed_stages
                        pct = 15 + (last_completed / 7) * 70
                        stage_names = [s.name for s in progress.stages]
                        stage_name = stage_names[-1] if stage_names else "Working..."
                        self.app.call_from_thread(self._update_stage,
                                                   stage_name, pct)
                        for s in progress.stages:
                            if s.findings_count > 0 and s.status == "done":
                                self.app.call_from_thread(self._log,
                                    f"  ✓ {s.name}: {s.findings_count} findings")
                    stop_polling.wait(0.1)

            poll_thread = threading.Thread(target=_poll_progress, daemon=True)
            poll_thread.start()

            try:
                if config.get("full", True):
                    result = orch.run_full()
                else:
                    result = orch.run()
            finally:
                stop_polling.set()

            self.app.call_from_thread(self._update_stage,
                                       "Aggregating results...", 90)
            self.app.call_from_thread(self._log,
                f"✓ Found {len(result.findings)} findings")
            self.app.call_from_thread(self._log,
                f"📋 Decision: {result.final_decision.value}")

            self.app.scan_result = result

            self.app.call_from_thread(self._update_stage, "✓ Scan complete!", 100)

            time.sleep(0.5)
            self.app.call_from_thread(self.app.switch_mode, "results")

        except Exception as e:
            self.app.call_from_thread(self._log,
                f"[red]❌ Error: {e}[/red]")
            import traceback
            self.app.call_from_thread(self._log,
                f"[dim]{traceback.format_exc()}[/dim]")

    def _update_stage(self, stage: str, progress_pct: int = 0) -> None:
        self.current_stage = stage
        self.query_one("#stage-label", Static).update(stage)
        pb = self.query_one("#scan-progress", ProgressBar)
        if progress_pct > 0:
            pb.update(progress=progress_pct)

    def _log(self, message: str) -> None:
        log = self.query_one("#scan-log", RichLog)
        log.write(message)
        if "Found" in message and "findings" in message:
            try:
                count = int(message.split("Found ")[1].split(" ")[0])
                self.findings_count = count
                self.query_one("#findings-label", Static).update(
                    f"{count} findings"
                )
            except (ValueError, IndexError):
                pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel-btn":
            self._cancel_scan()

    def action_cancel(self) -> None:
        self._cancel_scan()

    def _cancel_scan(self) -> None:
        if hasattr(self, "_scan_worker"):
            self._scan_worker.cancel()
        self.app.switch_mode("welcome")
