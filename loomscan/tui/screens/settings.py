"""Settings screen — configure LoomScan defaults."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Center, Middle
from textual.screen import Screen
from textual.widgets import Static, Button, Switch, Label, Checkbox
from textual.binding import Binding


class SettingsScreen(Screen):
    """Settings screen — configure default behavior."""

    CSS = """
    SettingsScreen {
        align: center middle;
        background: $surface;
    }

    SettingsScreen #main {
        width: 60;
        height: auto;
        padding: 2 4;
    }

    SettingsScreen #header {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }

    SettingsScreen .setting-row {
        height: 3;
        margin-bottom: 0;
    }

    SettingsScreen .setting-label {
        width: 1fr;
    }

    SettingsScreen #buttons {
        height: 3;
        align: center middle;
        margin-top: 2;
    }
    """

    BINDINGS = [
        Binding("escape", "back", "Back"),
    ]

    def compose(self) -> ComposeResult:
        with Center():
            with Middle():
                with Container(id="main"):
                    yield Static("⚙️  Settings", id="header")

                    yield Static("TUI Settings", classes="setting-label")
                    with Horizontal(classes="setting-row"):
                        yield Label("Show mascot animation",
                                   classes="setting-label")
                        yield Switch(True, id="set-mascot")

                    with Horizontal(classes="setting-row"):
                        yield Label("Auto-scroll log (follow tail)",
                                   classes="setting-label")
                        yield Switch(True, id="set-autoscroll")

                    yield Static("Scan Settings", classes="setting-label")
                    with Horizontal(classes="setting-row"):
                        yield Label("Full repo scan by default",
                                   classes="setting-label")
                        yield Switch(True, id="set-full")

                    with Horizontal(classes="setting-row"):
                        yield Label("Include secret detection",
                                   classes="setting-label")
                        yield Switch(True, id="set-secrets")

                    with Horizontal(id="buttons"):
                        yield Button("←  Back", id="back-btn")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back-btn":
            self.app.switch_mode("welcome")

    def action_back(self) -> None:
        self.app.switch_mode("welcome")
