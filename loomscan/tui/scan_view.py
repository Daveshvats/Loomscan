"""ScanView — shows scan progress in the content area.

v5.14: Replaces the full-screen scanning screen with a content-area widget
that fits in the MiMoCode-style layout. Shows:
- Mascot (small, top-right)
- Progress bar
- Live log output (scrollable)
"""
from __future__ import annotations

import os
import time
import threading
from pathlib import Path

from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Static, ProgressBar, RichLog
from textual.reactive import reactive
from textual.worker import Worker


class ScanView(Container):
    """Scan progress view — fits in the app's content area."""

    CSS = """
    ScanView {
        padding: 1 2;
    }

    ScanView #scan-header {
        color: $accent;
        text-style: bold;
        margin-bottom: 1;
    }

    ScanView #scan-top {
        height: 12;
        margin-bottom: 1;
    }

    ScanView #scan-mascot {
        width: 24;
        height: 100%;
        align: center middle;
        border: round $primary;
        padding: 1;
    }

    ScanView #scan-progress-area {
        width: 1fr;
        height: 100%;
        padding: 0 1;
        align: center middle;
    }

    ScanView #scan-stage {
        color: $accent;
        text-style: bold;
        margin-bottom: 1;
    }

    ScanView #scan-progress {
        margin-bottom: 1;
    }

    ScanView #scan-findings {
        color: $text-muted;
    }

    ScanView #scan-log-title {
        color: $accent;
        text-style: bold;
        margin-bottom: 0;
    }

    ScanView #scan-log {
        height: 1fr;
        border: round $primary;
        padding: 1;
        background: #111111;
    }
    """

    findings_count: reactive[int] = reactive(0)

    def __init__(self, repo_path: str, engine: str = "auto",
                 strictness: int = 5, full: bool = True):
        super().__init__()
        self._repo_path = repo_path
        self._engine = engine
        self._strictness = strictness
        self._full = full

    def compose(self):
        yield Static("🔍  Scanning...", id="scan-header")

        with Horizontal(id="scan-top"):
            with Container(id="scan-mascot"):
                try:
                    from .mascot_widget import MascotWidget
                    yield MascotWidget(id="mascot")
                except Exception:
                    yield Static("🕷️")

            with Vertical(id="scan-progress-area"):
                yield Static("Initializing...", id="scan-stage")
                yield ProgressBar(total=100, id="scan-progress",
                                 show_percentage=True)
                yield Static("0 findings", id="scan-findings")

        with Container(id="scan-log"):
            yield Static("📋  Scan Log", id="scan-log-title")
            yield RichLog(id="scan-log-output", highlight=True, markup=True)

    def on_mount(self) -> None:
        """Start the scan."""
        self.run_worker(self._run_scan, thread=True, exclusive=True)

    def _run_scan(self) -> None:
        """Run the scan in a background thread."""
        try:
            repo_path = Path(self._repo_path)

            # Engine selection
            if self._engine == "rust":
                os.environ["LOOMSCAN_ENGINE"] = "rust"
                self.app.call_from_thread(self._log,
                    "[cyan]🚀 Engine: Rust core[/cyan]")
            elif self._engine == "semgrep":
                os.environ["LOOMSCAN_ENGINE"] = "semgrep"
                self.app.call_from_thread(self._log,
                    "[cyan]🔍 Engine: Semgrep[/cyan]")
            elif self._engine == "python":
                os.environ["LOOMSCAN_ENGINE"] = "python"
                self.app.call_from_thread(self._log,
                    "[cyan]🐍 Engine: Python re[/cyan]")
            else:
                os.environ.pop("LOOMSCAN_ENGINE", None)
                self.app.call_from_thread(self._log,
                    "[cyan]⚙️ Engine: Auto-detect[/cyan]")

            from ..config import STCAConfig, find_config
            from ..orchestrator import Orchestrator
            from .progress import ScanProgress

            self.app.call_from_thread(self._update_stage,
                                       "Loading configuration...", 5)
            self.app.call_from_thread(self._log, f"📁 Scanning: {repo_path}")

            cfg = STCAConfig.from_file(find_config(repo_path))

            self.app.call_from_thread(self._update_stage,
                                       "Running scan layers...", 15)

            progress = ScanProgress(total_stages=7, enabled=False)
            orch = Orchestrator(repo_path, cfg,
                               strictness=self._strictness,
                               progress=progress)

            self.app.call_from_thread(self._log, "▶ Starting scan...")

            # Progress polling
            stop_polling = threading.Event()

            def _poll():
                last = 0
                while not stop_polling.is_set():
                    if progress.completed_stages > last:
                        last = progress.completed_stages
                        pct = 15 + (last / 7) * 70
                        names = [s.name for s in progress.stages]
                        name = names[-1] if names else "Working..."
                        self.app.call_from_thread(self._update_stage, name, pct)
                        for s in progress.stages:
                            if s.findings_count > 0 and s.status == "done":
                                self.app.call_from_thread(self._log,
                                    f"  ✓ {s.name}: {s.findings_count} findings")
                    stop_polling.wait(0.1)

            poll = threading.Thread(target=_poll, daemon=True)
            poll.start()

            try:
                if self._full:
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
            self.app.call_from_thread(self._update_stage, "✓ Complete!", 100)

            time.sleep(0.5)
            self.app.call_from_thread(self._show_results)

        except Exception as e:
            self.app.call_from_thread(self._log,
                f"[red]❌ Error: {e}[/red]")

    def _update_stage(self, stage: str, pct: int = 0) -> None:
        self.query_one("#scan-stage", Static).update(stage)
        pb = self.query_one("#scan-progress", ProgressBar)
        if pct > 0:
            pb.update(progress=pct)

    def _log(self, msg: str) -> None:
        log = self.query_one("#scan-log-output", RichLog)
        log.write(msg)
        if "Found" in msg and "findings" in msg:
            try:
                count = int(msg.split("Found ")[1].split(" ")[0])
                self.findings_count = count
                self.query_one("#scan-findings", Static).update(
                    f"{count} findings"
                )
            except (ValueError, IndexError):
                pass

    def _show_results(self) -> None:
        """Switch to results view."""
        from .results_view import ResultsView
        content = self.app.query_one("#content-area", Container)
        content.remove_children()
        if self.app.scan_result:
            content.mount(ResultsView(self.app.scan_result))
