"""Config screen — beautiful form with bordered sections.

v5.13: Redesigned with:
- Bordered sections (repo selection, options, engine, strictness)
- Responsive layout (1fr with min/max widths)
- Radio buttons in a styled group
- File picker integration
- Clean spacing
"""
from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical, Center, Middle
from textual.screen import Screen
from textual.widgets import (
    Static, Button, Input, Checkbox, Label, Switch, ProgressBar,
    RadioButton, RadioSet
)
from textual.binding import Binding
from textual.reactive import reactive


class ConfigScreen(Screen):
    """Configuration screen — pick repo + options via UI widgets."""

    CSS = """
    ConfigScreen {
        align: center middle;
    }

    ConfigScreen #main-box {
        width: 1fr;
        max-width: 80;
        min-width: 40;
        height: auto;
        max-height: 90%;
        padding: 1 2;
    }

    ConfigScreen #header {
        text-align: center;
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }

    ConfigScreen .section {
        border: round $primary;
        padding: 1;
        margin-bottom: 1;
        background: $panel;
    }

    ConfigScreen .section-title {
        color: $accent;
        text-style: bold;
        margin-bottom: 1;
    }

    ConfigScreen .section:last-child {
        margin-bottom: 0;
    }

    ConfigScreen #repo-row {
        height: 3;
    }

    ConfigScreen #repo-input {
        width: 1fr;
    }

    ConfigScreen #browse-btn {
        margin-left: 1;
        width: 12;
    }

    ConfigScreen .checkbox-row {
        margin-bottom: 0;
    }

    ConfigScreen RadioSet {
        margin-bottom: 0;
    }

    ConfigScreen #strictness-row {
        height: 3;
    }

    ConfigScreen #s-min, ConfigScreen #s-max {
        width: 3;
        text-align: center;
        color: $text-muted;
    }

    ConfigScreen #strictness-bar {
        width: 1fr;
    }

    ConfigScreen #strictness-value {
        text-align: center;
        color: $accent;
        text-style: bold;
        margin-top: 0;
    }

    ConfigScreen #buttons {
        height: 3;
        align: center middle;
        margin-top: 1;
    }

    ConfigScreen #start-btn {
        margin-right: 2;
    }

    ConfigScreen #status {
        color: $warning;
        text-align: center;
        margin-top: 1;
    }
    """

    BINDINGS = [
        Binding("escape", "back", "Back"),
        Binding("ctrl+s", "start", "Start"),
    ]

    repo_path: reactive[str] = reactive("")
    full_scan: reactive[bool] = reactive(True)
    include_secrets: reactive[bool] = reactive(True)
    strict_mode: reactive[bool] = reactive(False)
    generate_sarif: reactive[bool] = reactive(False)
    strictness: reactive[int] = reactive(5)
    engine_choice: reactive[str] = reactive("auto")

    def compose(self) -> ComposeResult:
        with Center():
            with Middle():
                with Container(id="main-box"):
                    yield Static("⚙️  Scan Configuration", id="header")

                    # === Repo Section ===
                    with Container(classes="section"):
                        yield Static("📁  Repository", classes="section-title")
                        with Horizontal(id="repo-row"):
                            yield Input(placeholder="/path/to/your/code",
                                      id="repo-input")
                            yield Button("Browse", id="browse-btn")

                    # === Options Section ===
                    with Container(classes="section"):
                        yield Static("🔧  Scan Options", classes="section-title")
                        yield Checkbox("Full repository scan (not just diff)",
                                     True, id="opt-full", classes="checkbox-row")
                        yield Checkbox("Include secret detection",
                                     True, id="opt-secrets", classes="checkbox-row")
                        yield Checkbox("Strict mode (fail on warnings)",
                                     False, id="opt-strict", classes="checkbox-row")
                        yield Checkbox("Generate SARIF report",
                                     False, id="opt-sarif", classes="checkbox-row")

                    # === Engine Section ===
                    with Container(classes="section"):
                        yield Static("🚀  YAML Rule Engine", classes="section-title")
                        yield RadioSet(
                            RadioButton("Auto (detect best available)", True,
                                       id="engine-auto"),
                            RadioButton("Rust core (10-50x faster, recommended)",
                                       id="engine-rust"),
                            RadioButton("Semgrep (full pattern-inside support)",
                                       id="engine-semgrep"),
                            RadioButton("Python re (always works, slowest)",
                                       id="engine-python"),
                            id="engine-radioset",
                        )

                    # === Strictness Section ===
                    with Container(classes="section"):
                        yield Static("📊  Strictness Level", classes="section-title")
                        with Horizontal(id="strictness-row"):
                            yield Label("1", id="s-min")
                            yield ProgressBar(total=9, id="strictness-bar")
                            yield Label("9", id="s-max")
                        yield Static("Level: 5", id="strictness-value")

                    # === Buttons ===
                    with Horizontal(id="buttons"):
                        yield Button("▶  Start Scan", id="start-btn",
                                    variant="primary")
                        yield Button("←  Back", id="back-btn")

                    yield Static("", id="status")

    def on_mount(self) -> None:
        self.repo_path = str(Path.cwd())
        self.query_one("#repo-input", Input).value = self.repo_path

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "repo-input":
            self.repo_path = event.value

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "opt-full":
            self.full_scan = event.value
        elif event.checkbox.id == "opt-secrets":
            self.include_secrets = event.value
        elif event.checkbox.id == "opt-strict":
            self.strict_mode = event.value
        elif event.checkbox.id == "opt-sarif":
            self.generate_sarif = event.value

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        """v5.13: Handle engine selection via RadioSet."""
        if event.radio_set.id == "engine-radioset":
            selected = event.pressed
            if selected and selected.id:
                self.engine_choice = selected.id.replace("engine-", "")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "browse-btn":
            self._browse()
        elif event.button.id == "start-btn":
            self._start_scan()
        elif event.button.id == "back-btn":
            self.app.switch_mode("welcome")

    def _browse(self) -> None:
        try:
            from textual_fspicker import SelectDirectory
            self.app.push_screen(SelectDirectory(), self._on_dir_selected)
        except ImportError:
            self.query_one("#status", Static).update(
                "File picker not available — type the path manually"
            )

    def _on_dir_selected(self, path: Path | None) -> None:
        if path:
            self.repo_path = str(path)
            self.query_one("#repo-input", Input).value = str(path)

    def _start_scan(self) -> None:
        status = self.query_one("#status", Static)
        if not self.repo_path:
            status.update("⚠️  Please enter a repository path")
            return
        repo = Path(self.repo_path).expanduser().resolve()
        if not repo.exists():
            status.update(f"⚠️  Path does not exist: {repo}")
            return
        if not repo.is_dir():
            status.update(f"⚠️  Not a directory: {repo}")
            return
        self.app.scan_config = {
            "repo": str(repo),
            "full": self.full_scan,
            "secrets": self.include_secrets,
            "strict": self.strict_mode,
            "sarif": self.generate_sarif,
            "strictness": self.strictness,
            "engine": self.engine_choice,
        }
        self.app.switch_mode("scanning")

    def action_back(self) -> None:
        self.app.switch_mode("welcome")

    def action_start(self) -> None:
        self._start_scan()
