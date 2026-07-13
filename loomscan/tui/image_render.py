"""Terminal inline-image renderer for Loomy the spider mascot.

v5.9: Supports real graphics in terminals that implement inline-image protocols:
  - Kitty graphics protocol (Kitty, Ghostty)
  - iTerm2 inline-image protocol (iTerm2, WezTerm)
  - Sixel (xterm with Sixel, mlterm)

Falls back to ASCII art on terminals that don't support any protocol
(plain Linux console, CI logs, piped output).

Terminal detection:
  - $TERM_PROGRAM == "iTerm.app" → iTerm2 protocol
  - $TERM_PROGRAM == "WezTerm" → iTerm2 protocol (WezTerm supports it)
  - $TERM_PROGRAM == "vscode" → try iTerm2 protocol (VS Code terminal supports it)
  - $TERM contains "kitty" → Kitty protocol
  - $TERM contains "ghostty" → Kitty protocol
  - $TERM_PROGRAM == "ghostty" → Kitty protocol
  - Otherwise: ASCII fallback

The renderer caches PNG frames in memory and transmits them via the
appropriate protocol. Animation is done by displaying frame N, sleeping,
then displaying frame N+1 (overwriting the previous frame).
"""
from __future__ import annotations

import base64
import io
import os
import sys
import zlib
import threading
import time
from pathlib import Path
from typing import Optional, List, Tuple

# Lazy import PIL only when needed (asset loading)
_PIL_AVAILABLE = None


def _check_pil() -> bool:
    global _PIL_AVAILABLE
    if _PIL_AVAILABLE is None:
        try:
            from PIL import Image  # noqa: F401
            _PIL_AVAILABLE = True
        except ImportError:
            _PIL_AVAILABLE = False
    return _PIL_AVAILABLE


# ============================================================================
# Terminal capability detection
# ============================================================================


def detect_terminal_protocol() -> str:
    """Detect which inline-image protocol the current terminal supports.

    Returns one of:
      "kitty"    — Kitty graphics protocol
      "iterm2"   — iTerm2 inline-image protocol
      "sixel"    — Sixel graphics (not yet implemented, falls back)
      "ascii"    — No inline image support, use ASCII art

    Detection is conservative — we only claim support if we're confident
    the terminal implements the protocol. False positives would produce
    garbage escape sequences in the user's terminal.
    """
    # Non-TTY → always ASCII (piped to file, CI log, etc.)
    if not sys.stdout.isatty():
        return "ascii"

    term = os.environ.get("TERM", "").lower()
    term_program = os.environ.get("TERM_PROGRAM", "").lower()
    lc_terminal = os.environ.get("LC_TERMINAL", "").lower()

    # Kitty graphics protocol
    # Kitty: TERM=xterm-kitty
    # Ghostty: TERM_PROGRAM=ghostty (also supports Kitty protocol)
    # WezTerm: supports Kitty protocol but also iTerm2
    if "kitty" in term or "kitty" in term_program:
        return "kitty"
    if "ghostty" in term_program or "ghostty" in term:
        return "kitty"

    # iTerm2 inline-image protocol
    # iTerm2: TERM_PROGRAM=iTerm.app
    # WezTerm: TERM_PROGRAM=WezTerm (supports iTerm2 protocol)
    # VS Code: TERM_PROGRAM=vscode (integrated terminal supports iTerm2 protocol)
    # Apple Terminal: TERM_PROGRAM=Apple_Terminal (does NOT support inline images)
    if term_program in ("iterm.app", "wezterm", "vscode"):
        return "iterm2"
    if lc_terminal == "iterm2":
        return "iterm2"

    # Sixel — we'd need to query the terminal with a DA2 request.
    # Conservative: only claim Sixel if TERM explicitly mentions it.
    if "sixel" in term:
        return "sixel"

    # Unknown terminal — fall back to ASCII
    return "ascii"


# ============================================================================
# Asset loading
# ============================================================================

_ASSETS_DIR = Path(__file__).resolve().parent / "assets"
_FRAMES_CACHE: Optional[List[bytes]] = None  # cached PNG bytes
_GIF_CACHE: Optional[bytes] = None


def _load_png_frames() -> List[bytes]:
    """Load all PNG frames from assets/frames/ into memory (cached)."""
    global _FRAMES_CACHE
    if _FRAMES_CACHE is not None:
        return _FRAMES_CACHE

    frames_dir = _ASSETS_DIR / "frames"
    if not frames_dir.exists():
        _FRAMES_CACHE = []
        return _FRAMES_CACHE

    frames = []
    for i in range(24):  # 24 frames expected
        path = frames_dir / f"frame_{i:02d}.png"
        if path.exists():
            frames.append(path.read_bytes())
        else:
            break

    _FRAMES_CACHE = frames
    return _FRAMES_CACHE


def _load_gif() -> bytes:
    """Load the optimized GIF (for terminals that support GIF directly)."""
    global _GIF_CACHE
    if _GIF_CACHE is not None:
        return _GIF_CACHE
    gif_path = _ASSETS_DIR / "loomy-spider-opt.gif"
    if gif_path.exists():
        _GIF_CACHE = gif_path.read_bytes()
    else:
        _GIF_CACHE = b""
    return _GIF_CACHE


# ============================================================================
# Kitty graphics protocol
# ============================================================================


def _kitty_render_png(png_bytes: bytes, width_cells: int = 20,
                       height_cells: int = 10) -> str:
    """Render a PNG using the Kitty graphics protocol.

    Kitty protocol escape sequence:
      ESC G a=T,f=100,s=<width_px>,v=<height_px>,c=<cols>,r=<rows>;<base64> ESC \\

    We transmit the PNG directly (f=100) and let Kitty scale it to the
    specified cell dimensions (c=cols, r=rows).
    """
    b64 = base64.b64encode(png_bytes).decode('ascii')
    # Split into chunks to avoid terminal buffer limits (max ~4096 bytes per chunk)
    chunk_size = 4096
    chunks = [b64[i:i+chunk_size] for i in range(0, len(b64), chunk_size)]

    parts = []
    for i, chunk in enumerate(chunks):
        if i == 0:
            # First chunk: include all the params
            params = f"a=T,f=100,c={width_cells},r={height_cells}"
            parts.append(f"\x1b_G{params};{chunk}")
        else:
            # Continuation chunks: m=1 means more chunks follow
            more = "m=1" if i < len(chunks) - 1 else "m=0"
            parts.append(f"\x1b_G{more};{chunk}")
    parts.append("\x1b\\")
    return "".join(parts)


def _kitty_clear_image(image_id: int = 1) -> str:
    """Clear a previously-rendered Kitty image.

    a=d means delete, i=<id> specifies which image to delete.
    """
    return f"\x1b_Ga=d,i={image_id}\x1b\\"


# ============================================================================
# iTerm2 inline-image protocol
# ============================================================================


def _iterm2_render_png(png_bytes: bytes, width: str = "auto",
                        height: str = "10") -> str:
    """Render a PNG using the iTerm2 inline-image protocol.

    iTerm2 OSC 1337 sequence:
      ESC ] 1337 ; File=inline=1;width=<w>;height=<h>:<base64> BEL

    Width/height can be:
      - "auto" (fit to image)
      - Npx (N pixels)
      - N% (percentage of terminal)
      - N (N cells)
    """
    b64 = base64.b64encode(png_bytes).decode('ascii')
    # iTerm2 wants width in cells or pixels. We use cells for consistency.
    return f"\x1b]1337;File=inline=1;width={width};height={height};preserveAspectRatio=1:{b64}\x07"


def _iterm2_clear_lines(n: int = 10) -> str:
    """Clear N terminal lines (to overwrite previous frame)."""
    # Move up N lines, then clear to end of screen
    return f"\x1b[{n}A\r\x1b[J"


# ============================================================================
# Sixel protocol (basic)
# ============================================================================


def _sixel_render_png(png_bytes: bytes) -> str:
    """Render a PNG as Sixel graphics.

    This requires converting PNG → Sixel format. We use PIL for the conversion
    if available; otherwise fall back to ASCII.

    Sixel is older and less common, so this is best-effort.
    """
    if not _check_pil():
        return ""
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(png_bytes))
        # Convert to palette mode for Sixel (max 256 colors)
        if img.mode != 'P':
            img = img.convert('P', palette=Image.ADAPTIVE, colors=256)
        # Write Sixel to a string buffer
        buf = io.BytesIO()
        # PIL doesn't have native Sixel output, so we'd need libsixel.
        # For now, return empty → caller falls back to ASCII.
        return ""
    except Exception:
        return ""


# ============================================================================
# Unified renderer
# ============================================================================


class ImageMascot:
    """Renders Loomy the spider as real graphics in supporting terminals.

    Falls back to ASCII art on terminals without inline-image support.

    Usage:
        im = ImageMascot(enabled=True)
        im.start_animation(phase="layers")
        ... do work ...
        im.stop_animation()
    """

    def __init__(self, enabled: bool = True, width_cells: int = 20,
                 height_cells: int = 10, anim_interval: float = 0.12):
        self.enabled = enabled
        self.width_cells = width_cells
        self.height_cells = height_cells
        self.anim_interval = anim_interval
        self.protocol = detect_terminal_protocol() if enabled else "ascii"
        self._anim_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._frame_idx = 0
        self._current_message: Optional[str] = None
        # Pre-load frames
        self._frames: List[bytes] = []
        if self.enabled and self.protocol in ("kitty", "iterm2"):
            self._frames = _load_png_frames()
            if not self._frames:
                # No frames available → fall back to ASCII
                self.protocol = "ascii"

    @property
    def supports_images(self) -> bool:
        """True if the terminal supports inline images and frames are loaded."""
        return self.protocol in ("kitty", "iterm2") and len(self._frames) > 0

    def render_frame(self, idx: int, message: Optional[str] = None) -> None:
        """Render a single frame of the spider animation.

        Args:
            idx: Frame index (0-23)
            message: Optional speech bubble message to print below the image
        """
        if not self.supports_images:
            return

        idx = idx % len(self._frames)
        png_bytes = self._frames[idx]

        if self.protocol == "kitty":
            # Clear previous frame (move cursor up and clear)
            sys.stdout.write(f"\x1b[{self.height_cells + 2}A\r\x1b[J")
            sys.stdout.write(_kitty_render_png(png_bytes,
                                                self.width_cells,
                                                self.height_cells))
            sys.stdout.write("\r\n")
            if message:
                sys.stdout.write(f"\x1b[36m  🕷️  {message}\x1b[0m\r\n")
            sys.stdout.flush()
        elif self.protocol == "iterm2":
            # Clear previous frame
            sys.stdout.write(_iterm2_clear_lines(self.height_cells + 2))
            sys.stdout.write(_iterm2_render_png(png_bytes))
            sys.stdout.write("\r\n")
            if message:
                sys.stdout.write(f"\x1b[36m  🕷️  {message}\x1b[0m\r\n")
            sys.stdout.flush()

    def start_animation(self, phase: str = "layers",
                         message: Optional[str] = None) -> None:
        """Start background animation thread."""
        if not self.supports_images:
            return
        self._current_message = message
        if self._anim_thread and self._anim_thread.is_alive():
            return
        self._stop_event.clear()
        self._anim_thread = threading.Thread(
            target=self._animate_loop, daemon=True
        )
        self._anim_thread.start()

    def stop_animation(self) -> None:
        """Stop the background animation."""
        if not self.supports_images:
            return
        self._stop_event.set()
        if self._anim_thread:
            self._anim_thread.join(timeout=1.0)
        self._anim_thread = None

    def update_message(self, message: str) -> None:
        """Update the speech bubble message without restarting animation."""
        self._current_message = message

    def _animate_loop(self) -> None:
        """Background loop that cycles through frames."""
        n = len(self._frames)
        while not self._stop_event.is_set():
            self.render_frame(self._frame_idx % n, self._current_message)
            self._frame_idx += 1
            self._stop_event.wait(self.anim_interval)

    def say(self, phase: str, message: Optional[str] = None) -> None:
        """Render a single static frame (for stage boundaries).

        Picks a frame based on phase:
          - init/discover → frame 0
          - layers/taint/cpg → frames 2-8 (cycling)
          - aggregate/llm → frame 12
          - done/warn/block/pass → frame 23 (last)
        """
        if not self.supports_images:
            return
        phase_to_frame = {
            "init": 0, "discover": 0,
            "layers": 4, "taint": 8, "cpg": 12, "metamorphic": 14,
            "aggregate": 16, "llm": 18, "autofix": 20,
            "done": 23, "warn": 23, "block": 23, "pass": 23,
        }
        frame_idx = phase_to_frame.get(phase, 0)
        self.render_frame(frame_idx, message)


def get_terminal_protocol() -> str:
    """Public API: return the detected terminal protocol name."""
    return detect_terminal_protocol()


def is_image_supported() -> bool:
    """Public API: return True if inline images will render."""
    return detect_terminal_protocol() in ("kitty", "iterm2")
