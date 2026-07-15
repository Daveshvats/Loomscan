"""Loomy mascot widget for Textual TUI.

v5.11: Three-tier mascot rendering:
  1. Image terminals (Kitty, iTerm2, WezTerm, VS Code, Ghostty):
     → PNG frames via textual-image, swap every 120ms for animation
  2. All other TTY terminals (macOS Terminal, Windows Terminal, GNOME, etc.):
     → Colored braille spider ASCII art (from user-supplied art)
  3. Dumb/CI/non-TTY: no mascot at all (clean output)

The mascot uses Textual's reactive attributes + set_interval for smooth
animation without blocking the event loop.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Static
from rich.text import Text

_ASSETS_DIR = Path(__file__).resolve().parent / "assets"


def _detect_image_support() -> bool:
    """Check if the terminal supports inline images (Kitty/iTerm2 protocols)."""
    if not sys.stdout.isatty():
        return False
    term = os.environ.get("TERM", "").lower()
    term_program = os.environ.get("TERM_PROGRAM", "").lower()
    if "kitty" in term or "ghostty" in term_program:
        return True
    if term_program in ("iterm.app", "wezterm", "vscode"):
        return True
    return False


def _load_ascii_spider() -> str:
    """Load the braille spider ASCII art."""
    path = _ASSETS_DIR / "loomy-spider-ascii.txt"
    if path.exists():
        return path.read_text(encoding="utf-8")
    return "🕷️ Loomy"


def _load_png_frames() -> list:
    """Load PNG frame paths for image rendering."""
    frames_dir = _ASSETS_DIR / "frames"
    if not frames_dir.exists():
        return []
    return sorted(frames_dir.glob("frame_*.png"))


class MascotWidget(Widget):
    """Animated Loomy the spider mascot.

    Renders as:
    - PNG image animation on Kitty/iTerm2/WezTerm/VS Code
    - Colored braille ASCII art on all other TTY terminals
    - Nothing on dumb/CI/non-TTY (use MascotWidget(visible=False))

    The spider has a subtle "breathing" animation (opacity pulse) and
    the image version cycles through 24 PNG frames.
    """

    DEFAULT_CSS = """
    MascotWidget {
        width: auto;
        height: auto;
        content-align: center middle;
        padding: 0 2;
    }

    MascotWidget.hidden {
        display: none;
    }

    MascotWidget .ascii-spider {
        color: $accent;
        text-align: center;
    }

    MascotWidget .ascii-spider-glow {
        color: $accent;
        text-style: bold;
    }
    """

    frame_idx: reactive[int] = reactive(0)
    breathing: reactive[float] = reactive(1.0)

    def __init__(self, id: str | None = None, enabled: bool = True):
        super().__init__(id=id)
        self._enabled = enabled and sys.stdout.isatty()
        self._supports_images = _detect_image_support() if self._enabled else False
        self._ascii_art = _load_ascii_spider()
        self._png_frames = _load_png_frames() if self._supports_images else []
        self._frame_timer = None
        self._breath_timer = None

    def compose(self):
        """Compose the mascot content."""
        if not self._enabled:
            # Dumb terminal: render nothing
            yield Static("")
            return

        if self._supports_images and self._png_frames:
            # Image mode: use textual-image widget
            try:
                from textual_image.widget import Image
                # Show first frame initially
                yield Image.from_file(str(self._png_frames[0]), id="mascot-image")
            except Exception:
                # Fallback to ASCII if image widget fails
                yield Static(self._get_colored_ascii(), id="mascot-ascii",
                            markup=True)
        else:
            # ASCII mode: colored braille spider
            yield Static(self._get_colored_ascii(), id="mascot-ascii",
                        markup=True)

    def on_mount(self):
        """Start animation timers."""
        if not self._enabled:
            return

        if self._supports_images and self._png_frames:
            # Image animation: cycle through PNG frames every 120ms
            self._frame_timer = self.set_interval(
                0.12, self._advance_image_frame
            )
        else:
            # ASCII animation: subtle opacity pulse (breathing effect)
            self._breath_timer = self.set_interval(
                1.5, self._pulse_breathing
            )

    def _advance_image_frame(self) -> None:
        """Cycle to the next PNG frame.

        v5.12 FIX: textual_image.widget.Image.image expects a PIL Image object,
        not a string path. We use Image.from_file() to create a new image
        instance and assign it.
        """
        self.frame_idx = (self.frame_idx + 1) % len(self._png_frames)
        try:
            from textual_image.widget import Image
            img_widget = self.query_one("#mascot-image", Image)
            # v5.12: Use from_file() to create a proper image object
            new_img = Image.from_file(str(self._png_frames[self.frame_idx]))
            img_widget.image = new_img.image
        except Exception:
            pass

    def _pulse_breathing(self) -> None:
        """Subtle breathing animation for ASCII mascot."""
        # Toggle between opacity 1.0 and 0.85 for a gentle "breathing" effect
        self.styles.animate(
            "opacity",
            value=0.85 if self.breathing == 1.0 else 1.0,
            duration=1.5,
            easing="in_out_sine",
            on_complete=lambda: setattr(self, "breathing",
                                        0.85 if self.breathing == 1.0 else 1.0)
        )

    def _get_colored_ascii(self) -> str:
        """Get the ASCII spider with Rich color markup.

        The braille spider is rendered in accent color with a subtle
        gradient effect using Rich markup.
        """
        # Use Rich markup to color the spider
        # $accent is a Textual design token (cyan/blue by default)
        # We use a cyan-to-blue gradient feel
        art = self._ascii_art.rstrip()
        # Color the entire spider in bright cyan with bold for prominence
        return f"[bold bright_cyan]{art}[/bold bright_cyan]"

    def say(self, message: str) -> None:
        """Show a speech bubble message next to the spider."""
        # For now, just log it — the scanning screen will show messages
        # in a separate panel
        pass

