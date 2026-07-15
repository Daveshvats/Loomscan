"""Welcome screen — beautiful landing page with mascot + menu.

v5.13: Redesigned with:
- Bordered panel layout
- Responsive centering (works on any terminal size)
- Gradient title with accent color
- Animated mascot in a framed panel
- Menu buttons with icons
- Footer with keybindings
"""
from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Container, Center, Middle, Vertical, Horizontal
from textual.screen import Screen
from textual.widgets import Static, Button, Label
from textual.binding import Binding
from rich.text import Text
from rich.panel import Panel
from rich.align import Align

from ..mascot_widget import MascotWidget


class WelcomeScreen(Screen):
    """Welcome screen — shows mascot + main menu."""

    CSS = """
    WelcomeScreen {
        align: center middle;
    }

    WelcomeScreen #main-box {
        width: 1fr;
        max-width: 80;
        min-width: 40;
        height: auto;
        align: center middle;
        padding: 1 2;
    }

    WelcomeScreen #title-panel {
        border: round $accent;
        padding: 1 2;
        margin-bottom: 1;
        background: $boost;
        text-align: center;
    }

    WelcomeScreen #title {
        text-align: center;
        text-style: bold;
        color: $accent;
        margin-bottom: 0;
    }

    WelcomeScreen #subtitle {
        text-align: center;
        color: $text-muted;
    }

    WelcomeScreen #mascot-panel {
        border: round $primary;
        padding: 1;
        margin-bottom: 1;
        height: 20;
        align: center middle;
        background: $panel;
    }

    WelcomeScreen #menu-panel {
        border: round $accent;
        padding: 1 2;
        background: $panel;
    }

    WelcomeScreen .menu-button {
        width: 100%;
        margin-bottom: 1;
    }

    WelcomeScreen .menu-button:last-child {
        margin-bottom: 0;
    }

    WelcomeScreen #version-info {
        text-align: center;
        color: $text-muted;
        margin-top: 1;
    }

    WelcomeScreen #tagline {
        text-align: center;
        color: $success;
        text-style: italic;
        margin-top: 0;
    }
    """

    BINDINGS = [
        Binding("1", "scan", "Scan"),
        Binding("2", "results", "Results"),
        Binding("3", "settings", "Settings"),
        Binding("q", "quit", "Quit"),
        Binding("escape", "quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        with Center():
            with Middle():
                with Container(id="main-box"):

                    # Title panel
                    with Container(id="title-panel"):
                        yield Static("🕷️  LoomScan", id="title",
                                    markup=True)
                        yield Static("Static + Test + Constraint Analysis",
                                    id="subtitle")

                    # Mascot panel
                    with Container(id="mascot-panel"):
                        yield MascotWidget(id="mascot")

                    # Menu panel
                    with Container(id="menu-panel"):
                        yield Button("🔍  Scan a Repository",
                                   id="btn-scan", variant="primary",
                                   classes="menu-button")
                        yield Button("📊  View Recent Results",
                                   id="btn-results",
                                   classes="menu-button")
                        yield Button("⚙️  Settings",
                                   id="btn-settings",
                                   classes="menu-button")
                        yield Button("🚪  Quit",
                                   id="btn-quit", variant="error",
                                   classes="menu-button")

                    yield Static("v5.13  •  Press 1-4 or click an option",
                               id="version-info")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-scan":
            self.app.switch_mode("config")
        elif event.button.id == "btn-results":
            self.app.switch_mode("results")
        elif event.button.id == "btn-settings":
            self.app.switch_mode("settings")
        elif event.button.id == "btn-quit":
            self.app.exit()

    def action_scan(self) -> None:
        self.app.switch_mode("config")

    def action_results(self) -> None:
        self.app.switch_mode("results")

    def action_settings(self) -> None:
        self.app.switch_mode("settings")

    def action_quit(self) -> None:
        self.app.exit()
