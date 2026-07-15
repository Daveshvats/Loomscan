"""LoomScan TUI App — MiMoCode-inspired design.

v5.15: Complete redesign based on MiMo-Code's TUI:
  - ASCII art logo (block chars) centered at top
  - Input prompt below logo (centered, max-width 75)
  - Command palette (Ctrl+P or /) — search-filterable, all commands
  - First-run config wizard (creates .loomscan.yaml)
  - Status bar at bottom (engine, strictness, working directory)
  - Footer with keyboard shortcuts

Every CLI command is accessible from the TUI via the command palette.
"""
from __future__ import annotations

import sys
import os
from pathlib import Path
from typing import Optional

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical, Horizontal, Center, Middle
from textual.widgets import Header, Footer, Static, Input, Label, RichLog
from textual.reactive import reactive
from textual.screen import ModalScreen

from .logo import get_logo_text
from .command_palette import CommandPalette
from .wizard import FirstRunWizard
from .scan_view import ScanView
from .results_view import ResultsView


class LoomScanApp(App):
    """LoomScan TUI — MiMoCode-style interface.

    Layout:
    ┌─────────────────────────────────────┐
    │                                     │
    │     ███╗   ███╗ ██████╗ ...         │  ← ASCII logo (centered)
    │     ████╗ ████║██╔═══██╗ ...        │
    │     (LOOMSCAN block art)            │
    │                                     │
    │  ▸ Type a command or / for help     │  ← Input prompt
    │                                     │
    ├─────────────────────────────────────┤
    │ 🚀 Rust · 📊 L5 · 📁 ~/code  v5.15  │  ← Status bar
    ├─────────────────────────────────────┤
    │ / commands  ctrl+p palette  q quit  │  ← Footer
    └─────────────────────────────────────┘
    """

    CSS = """
    Screen {
        background: #0a0a0a;
        color: #e0e0e0;
    }

    #logo-area {
        height: auto;
        align: center middle;
        padding: 2 0;
    }

    #logo-text {
        text-align: center;
        color: $accent;
    }

    #content-area {
        height: 1fr;
        padding: 0 2;
    }

    #input-area {
        height: auto;
        padding: 1 2;
        align: center middle;
    }

    #main-input-wrapper {
        width: 1fr;
        max-width: 75;
    }

    #main-input {
        height: 3;
        border: round $accent;
        background: #1a1a1a;
        color: #ffffff;
    }

    #main-input:focus {
        border: round $accent;
        background: #222222;
    }

    #status-bar {
        height: 1;
        background: #0a0a0a;
        color: #888888;
        padding: 0 2;
    }

    #status-engine {
        color: $accent;
    }

    Footer {
        background: #0a0a0a;
    }
    """

    TITLE = "LoomScan"

    BINDINGS = [
        Binding("ctrl+p", "palette", "Commands", show=True, priority=True),
        Binding("slash", "palette", "Commands", show=False, priority=True),
        Binding("ctrl+c", "quit", "Quit", show=False, priority=True),
    ]

    def __init__(self):
        super().__init__()
        self.scan_config: Optional[dict] = None
        self.scan_result = None
        self.working_dir = str(Path.cwd())
        self.engine = "auto"
        self.strictness = 5
        self._is_first_run = False

    def compose(self) -> ComposeResult:
        yield Container(
            Static(get_logo_text(color="bold $accent"), id="logo-text"),
            id="logo-area"
        )
        yield Container(id="content-area")
        yield Container(
            Container(
                Input(
                    placeholder="Type a command or / for commands  (e.g. scan, results, doctor)",
                    id="main-input",
                ),
                id="main-input-wrapper",
            ),
            id="input-area"
        )
        yield Static(
            f"  🚀 [b]Auto[/b]  ·  📊 Level {self.strictness}  ·  📁 {self.working_dir}  ·  v5.15",
            id="status-bar",
            markup=True
        )
        yield Footer()

    def on_mount(self) -> None:
        """Check for first-run and show welcome."""
        # Check if .loomscan.yaml exists
        cfg_path = Path(self.working_dir) / ".loomscan.yaml"
        if not cfg_path.exists():
            self._is_first_run = True
            self._show_welcome(first_run=True)
        else:
            self._show_welcome()
        # Focus the input
        self.query_one("#main-input", Input).focus()

    def _show_welcome(self, first_run: bool = False) -> None:
        """Show welcome content in the content area."""
        content = self.query_one("#content-area", Container)
        content.remove_children()

        if first_run:
            welcome_text = (
                "\n"
                "  [green]✓ Welcome to LoomScan![/green]\n\n"
                "  No configuration file found. Let's set up your project.\n\n"
                "  [bold yellow]Type 'wizard' to run the config wizard,[/bold yellow]\n"
                "  [dim]or type 'scan' to use defaults and start scanning.[/dim]\n\n"
                "  [dim]Available commands:[/dim]\n"
                "  [bold]  wizard[/bold]     — Run first-run setup wizard\n"
                "  [bold]  scan[/bold]       — Scan this directory (uses defaults)\n"
                "  [bold]  /[/bold]          — Open command palette\n"
                "  [bold]  doctor[/bold]     — Check system health\n\n"
            )
        else:
            welcome_text = (
                "\n"
                "  [green]✓ Ready to scan![/green]\n\n"
                "  [dim]Type a command to get started:[/dim]\n\n"
                "  [bold]  scan[/bold]       — Scan this repository\n"
                "  [bold]  results[/bold]    — View last scan results\n"
                "  [bold]  /[/bold]          — Open command palette (all commands)\n"
                "  [bold]  doctor[/bold]     — Check system health\n"
                "  [bold]  settings[/bold]   — View settings\n\n"
            )
        content.mount(Static(welcome_text, markup=True))

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle user input."""
        text = event.value.strip()
        if not text:
            return

        event.input.value = ""

        parts = text.split(None, 1)
        cmd = parts[0].lower().lstrip("/")
        arg = parts[1] if len(parts) > 1 else ""

        self._handle_command(cmd, arg)

    def _handle_command(self, cmd: str, arg: str) -> None:
        """Route a command to the appropriate handler."""
        # === Scan commands ===
        if cmd in ("scan", "run"):
            repo = arg if arg else self.working_dir
            self._show_scanning(repo)
        elif cmd == "scan_diff":
            self._show_scanning(self.working_dir, full=False)
        elif cmd == "quickstart":
            self._show_scanning(self.working_dir)

        # === Results ===
        elif cmd == "results":
            self._show_results()
        elif cmd == "export_sarif":
            self._export("sarif")
        elif cmd == "export_json":
            self._export("json")
        elif cmd == "dashboard":
            self._generate_dashboard()
        elif cmd == "summary":
            self._show_summary()

        # === Config ===
        elif cmd == "settings":
            self._show_settings()
        elif cmd == "init":
            self._init_config()
        elif cmd == "wizard":
            self._run_wizard()
        elif cmd == "strictness":
            self._set_strictness(arg)
        elif cmd == "engine":
            self._set_engine(arg)
        elif cmd == "cd":
            self._change_dir(arg)
        elif cmd == "gate":
            self._run_gate(arg)

        # === Analysis ===
        elif cmd in ("taint", "cpg", "metamorphic", "differential", "nullness",
                      "consistency", "deadcode", "typestate", "contracts", "rca",
                      "impact", "architecture"):
            self._run_analysis(cmd, arg)

        # === Security ===
        elif cmd in ("secrets", "flawfinder", "malicious", "pii",
                      "missing_patches", "missing-patches", "toxicity",
                      "ffi_check", "ffi-check"):
            cmd_normalized = cmd.replace("-", "_")
            self._run_analysis(cmd_normalized, arg)

        # === Quality ===
        elif cmd in ("code_quality", "code-quality", "duplicates", "doc_audit",
                      "doc-audit", "business_logic", "business-logic", "crypto",
                      "concurrency"):
            cmd_normalized = cmd.replace("-", "_")
            self._run_analysis(cmd_normalized, arg)

        # === Supply Chain ===
        elif cmd in ("supply_chain", "supply-chain", "sbom", "maven_cve",
                      "maven-cve"):
            cmd_normalized = cmd.replace("-", "_")
            self._run_analysis(cmd_normalized, arg)

        # === Infra ===
        elif cmd in ("iac", "config_scan", "config-scan", "modern"):
            cmd_normalized = cmd.replace("-", "_")
            self._run_analysis(cmd_normalized, arg)

        # === System ===
        elif cmd == "doctor":
            self._run_doctor()
        elif cmd in ("install_tools", "install-tools"):
            self._install_tools()
        elif cmd == "fix":
            self._run_fix()
        elif cmd == "monorepo":
            self._show_monorepo()
        elif cmd == "watch":
            self._show_watch()
        elif cmd == "lsp":
            self._start_lsp()

        # === Rules ===
        elif cmd == "mine":
            self._run_mine()
        elif cmd == "spec":
            self._run_spec()
        elif cmd in ("rule_lint", "rule-lint"):
            self._run_rule_lint()
        elif cmd == "playground":
            self._show_playground()
        elif cmd == "bot":
            self._run_bot()
        elif cmd == "submit":
            self._submit_pack(arg)

        # === Session ===
        elif cmd == "help":
            self._show_help()
        elif cmd in ("quit", "exit", "q"):
            self.exit()
        else:
            self._show_error(f"Unknown command: {cmd}. Type '/' for available commands.")

    def _show_scanning(self, repo_path: str, full: bool = True) -> None:
        """Start scanning."""
        content = self.query_one("#content-area", Container)
        content.remove_children()
        content.mount(ScanView(repo_path, self.engine, self.strictness, full))

    def _show_results(self) -> None:
        """Show scan results."""
        content = self.query_one("#content-area", Container)
        content.remove_children()
        if self.scan_result:
            content.mount(ResultsView(self.scan_result))
        else:
            content.mount(Static(
                "\n  [yellow]No scan results yet. Run 'scan' first.[/yellow]\n",
                markup=True))

    def _show_settings(self) -> None:
        """Show settings panel."""
        content = self.query_one("#content-area", Container)
        content.remove_children()
        engine_label = {"auto": "Auto-detect", "rust": "Rust core",
                       "semgrep": "Semgrep", "python": "Python re"}.get(self.engine, "Auto")
        content.mount(Static(
            f"\n  [bold $accent]⚙️  Settings[/bold $accent]\n\n"
            f"  📁 Working directory: [bold]{self.working_dir}[/bold]\n"
            f"  🚀 Engine: [bold]{engine_label}[/bold]\n"
            f"  📊 Strictness: [bold]{self.strictness}[/bold]\n\n"
            "  [dim]Commands:[/dim]\n"
            "  [bold]  cd <path>[/bold]          — Change working directory\n"
            "  [bold]  engine <choice>[/bold]    — Set engine (auto/rust/semgrep/python)\n"
            "  [bold]  strictness <1-9>[/bold]   — Set strictness level\n"
            "  [bold]  wizard[/bold]             — Run config wizard\n\n",
            markup=True))

    def _show_error(self, msg: str) -> None:
        content = self.query_one("#content-area", Container)
        content.remove_children()
        content.mount(Static(f"\n  [red]❌ {msg}[/red]\n", markup=True))

    def _run_wizard(self) -> None:
        """Open the first-run config wizard."""
        def _on_result(data):
            if data:
                content = self.query_one("#content-area", Container)
                content.remove_children()
                content.mount(Static(
                    "\n  [green]✓ Configuration saved![/green]\n\n"
                    "  [dim]Your .loomscan.yaml has been created. Type 'scan' to start.[/dim]\n",
                    markup=True))
        self.push_screen(FirstRunWizard(self.working_dir), _on_result)

    def action_palette(self) -> None:
        """Open the command palette."""
        def _on_result(cmd_id: str | None):
            if cmd_id:
                self._handle_command(cmd_id, "")
        self.push_screen(CommandPalette(), _on_result)

    def _change_dir(self, path: str) -> None:
        if path:
            new_path = Path(path).expanduser().resolve()
            if new_path.exists() and new_path.is_dir():
                self.working_dir = str(new_path)
                self._update_status()
                self._show_settings()
            else:
                self._show_error(f"Directory not found: {path}")

    def _set_engine(self, choice: str) -> None:
        if choice in ("auto", "rust", "semgrep", "python"):
            self.engine = choice
            self._update_status()
            self._show_settings()
        else:
            self._show_error("Engine must be: auto, rust, semgrep, or python")

    def _set_strictness(self, arg: str) -> None:
        try:
            level = max(1, min(9, int(arg)))
            self.strictness = level
            self._update_status()
            self._show_settings()
        except ValueError:
            self._show_error("Strictness must be a number 1-9")

    def _update_status(self) -> None:
        engine_label = {"auto": "Auto", "rust": "Rust core",
                       "semgrep": "Semgrep", "python": "Python re"}.get(self.engine, "Auto")
        status = self.query_one("#status-bar", Static)
        status.update(
            f"  🚀 [b]{engine_label}[/b]  ·  📊 Level {self.strictness}  ·  📁 {self.working_dir}  ·  v5.15",
            markup=True)

    def _init_config(self) -> None:
        """Create default .loomscan.yaml."""
        try:
            from ..config import STCAConfig
            cfg = STCAConfig.default()
            cfg_path = Path(self.working_dir) / ".loomscan.yaml"
            cfg.save(cfg_path)
            content = self.query_one("#content-area", Container)
            content.remove_children()
            content.mount(Static(
                f"\n  [green]✓ Created {cfg_path}[/green]\n",
                markup=True))
        except Exception as e:
            self._show_error(f"Failed to create config: {e}")

    def _run_doctor(self) -> None:
        """Run doctor and show output."""
        content = self.query_one("#content-area", Container)
        content.remove_children()
        log = RichLog(highlight=True, markup=True)
        content.mount(log)
        log.write("[bold $accent]🩺 Running doctor...[/bold $accent]")
        try:
            import subprocess
            result = subprocess.run(
                [sys.executable, "-m", "loomscan.cli", "doctor"],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.split("\n"):
                if line.strip():
                    log.write(line)
        except Exception as e:
            log.write(f"[red]Error: {e}[/red]")

    def _run_analysis(self, cmd: str, arg: str) -> None:
        """Run an analysis command and show output."""
        content = self.query_one("#content-area", Container)
        content.remove_children()
        log = RichLog(highlight=True, markup=True)
        content.mount(log)
        log.write(f"[bold $accent]🔍 Running {cmd}...[/bold $accent]")
        try:
            import subprocess
            cmd_arg = cmd.replace("_", "-")
            result = subprocess.run(
                [sys.executable, "-m", "loomscan.cli", cmd_arg, "--repo", self.working_dir],
                capture_output=True, text=True, timeout=60
            )
            for line in result.stdout.split("\n"):
                if line.strip():
                    log.write(line)
            if result.returncode != 0:
                log.write(f"[red]Exit code: {result.returncode}[/red]")
        except subprocess.TimeoutExpired:
            log.write("[yellow]Command timed out (60s)[/yellow]")
        except Exception as e:
            log.write(f"[red]Error: {e}[/red]")

    def _export(self, fmt: str) -> None:
        """Export results."""
        if not self.scan_result:
            self._show_error("No scan results to export. Run 'scan' first.")
            return
        try:
            if fmt == "sarif":
                from ..report.sarif import save_sarif
                path = Path(self.working_dir) / "loomscan-report.sarif"
                save_sarif(self.scan_result, Path(self.working_dir), path)
            else:
                import json
                path = Path(self.working_dir) / "loomscan-report.json"
                path.write_text(json.dumps(self.scan_result.to_dict(), indent=2))
            content = self.query_one("#content-area", Container)
            content.remove_children()
            content.mount(Static(
                f"\n  [green]✓ Exported to {path}[/green]\n", markup=True))
        except Exception as e:
            self._show_error(f"Export failed: {e}")

    def _show_help(self) -> None:
        """Show help."""
        content = self.query_one("#content-area", Container)
        content.remove_children()
        content.mount(Static(
            "\n  [bold $accent]❓  Help[/bold $accent]\n\n"
            "  [bold]Commands:[/bold]\n"
            "  [bold]  scan[/bold]           — Scan the repository\n"
            "  [bold]  results[/bold]        — View scan results\n"
            "  [bold]  doctor[/bold]         — Check system health\n"
            "  [bold]  settings[/bold]       — View/edit settings\n"
            "  [bold]  wizard[/bold]         — Run config wizard\n"
            "  [bold]  /[/bold]              — Open command palette (ALL commands)\n\n"
            "  [bold]Settings:[/bold]\n"
            "  [bold]  cd <path>[/bold]      — Change directory\n"
            "  [bold]  engine <choice>[/bold]— Switch engine\n"
            "  [bold]  strictness <N>[/bold] — Set level (1-9)\n\n"
            "  [bold]Shortcuts:[/bold]\n"
            "  [bold]  Ctrl+P[/bold]         — Command palette\n"
            "  [bold]  /[/bold]              — Command palette\n"
            "  [bold]  q[/bold]              — Quit\n\n",
            markup=True))

    # Stubs for commands that need full implementation
    def _generate_dashboard(self): self._run_analysis("dashboard", "")
    def _show_summary(self): self._run_analysis("summary", "")
    def _run_gate(self, arg): self._run_analysis("gate", arg)
    def _install_tools(self): self._run_analysis("install-tools", "")
    def _run_fix(self): self._run_analysis("fix", "")
    def _show_monorepo(self): self._run_analysis("monorepo", "")
    def _show_watch(self): self._show_error("Watch mode not available in TUI. Use: loomscan watch")
    def _start_lsp(self): self._show_error("LSP server not available in TUI. Use: loomscan lsp")
    def _run_mine(self): self._run_analysis("mine", "")
    def _run_spec(self): self._run_analysis("spec", "")
    def _run_rule_lint(self): self._run_analysis("rule-lint", "")
    def _show_playground(self): self._show_error("Playground not available in TUI. Use: loomscan playground")
    def _run_bot(self): self._show_error("Bot mode not available in TUI. Use: loomscan bot")
    def _submit_pack(self, arg): self._show_error("Use CLI: loomscan submit --pack <path>")


def launch_tui() -> int:
    """Launch the LoomScan TUI app."""
    try:
        app = LoomScanApp()
        app.run()
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        print(f"LoomScan TUI error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return 1
