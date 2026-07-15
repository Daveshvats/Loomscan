"""Loomy — the LoomScan mascot.

An ASCII spider that weaves a web of analysis. Like the mascots in claude-code
and opencode, Loomy shows different frames while the pipeline runs and prints
a final verdict when the scan completes. Loomy is non-blocking — animation
runs only when stdout is a TTY and `--no-tui` is not set.

v5.8 redesign: Loomy is now clearly a SPIDER (8 legs, spinneret, fangs) and
the web grows frame-by-frame as the analysis progresses. Each frame shows:
  - A spider with 8 articulated legs (4 per side)
  - A web being woven — starts as 2 strands, grows to a full orb web
  - The spider's position shifts as it moves between anchor points

The mascot is 9 lines tall and 36 chars wide — fits in any 80-col terminal.
"""
from __future__ import annotations

import sys
import threading
import time
from typing import Optional, List

try:
    from rich.console import Console
    from rich.text import Text
    from rich.panel import Panel
    from rich.align import Align
    _HAS_RICH = True
except ImportError:
    _HAS_RICH = False


# ============================================================================
# 8-frame weaving cycle
# ============================================================================
#
# Each frame is 9 lines. The spider (Loomy) sits in the center with 8 legs.
# A web grows around it: frame 0 has just 2 anchor strands, frame 7 has a
# full orb web with radial spokes + spiral thread.
#
# Legend:
#   /  \  |  -  = web strands
#   *  .  = web nodes / dewdrops
#   (  )  = spider abdomen + cephalothorax
#   ^  ^  = eyes (or - - when focused, ^ ^ when celebrating)
#   /\ \/ = articulated legs (8 total: 4 left, 4 right)
#   ~  = spinneret thread (the silk being laid down)

_MASCOT_FRAMES: List[str] = [
    # ----------------------------------------------------------------
    # Frame 0: Spider appears, drops first 2 anchor strands
    # ----------------------------------------------------------------
    r"""
         *                 *
          \               /
           \             /
            \    ___    /
             \  (-_-)  /
              \ /   \ /
               (     )
              /| \ / |\
             / |  ~  | \
            /  |     |  \
               |     |
               *     *
    """,
    # ----------------------------------------------------------------
    # Frame 1: Add 2 more anchor strands (X pattern), spider drops down
    # ----------------------------------------------------------------
    r"""
         *--------*--------*
          \       |       /
           \      |      /
            \   _(-_-)_  /
             \ /       \ /
              (         )
              |\  ~~~  /|
              | \     / |
              |  \   /  |
              |   \ /   |
              *----*----*
    """,
    # ----------------------------------------------------------------
    # Frame 2: Radial spokes forming (8 spokes), spider at top
    # ----------------------------------------------------------------
    r"""
              *--------*
            / |    .   | \
          /   |   . .  |   \
        *-----+--(-_-)--+-----*
          \   |  . . . |   /
            \ | . . . .| /
              *---| |---*
                  | |
                 /   \
                *     *
              spider moving
    """,
    # ----------------------------------------------------------------
    # Frame 3: Spider adds inner spiral ring (sticky capture spiral)
    # ----------------------------------------------------------------
    r"""
              *--------*
            / |  ....  | \
          /   | .    . |   \
        *-----.  (-_-) .-----*
          \   | .    . |   /
            \ |  ....  | /
              *---| |---*
                  |~|
                 /   \
                *     *
              weaving ring
    """,
    # ----------------------------------------------------------------
    # Frame 4: Second spiral ring added, spider on right side
    # ----------------------------------------------------------------
    r"""
              *--------*
            / | ...... | \
          /   |.      .|   \
        *-----.  /  \ .-----*
          \   |.( -  ).|   /  <-- spider here
            \ |. \  / .| /
              *--| |---*
                 |~|
                /   \
               *     *
              2nd ring
    """,
    # ----------------------------------------------------------------
    # Frame 5: Third ring, web is 60% complete
    # ----------------------------------------------------------------
    r"""
              *--------*
            / |........| \
          /   |.      .|   \
        *-----.( -  -).-----*
          \   |. \  / .|   /
            \ |...\/...| /
              *--|  |--*
                 | ~|
                /   \
               *     *
              3rd ring
    """,
    # ----------------------------------------------------------------
    # Frame 6: Web nearly complete, spider adds final touches
    # ----------------------------------------------------------------
    r"""
              *--------*
            / |........| \
          /   |. ..  ..|   \
        *-----.( -_- ).-----*
          \   |. ..  ..|   /
            \ |........| /
              *--|  |--*
                 | ~|
                /   \
               *     *
              almost done
    """,
    # ----------------------------------------------------------------
    # Frame 7: Web complete! Spider sits proudly in center, eyes happy
    # ----------------------------------------------------------------
    r"""
              *--------*
            / |^^^^^^^^| \
          /   |^      ^|   \
        *-----^( ^-^ )^-----*
          \   |^      ^|   /
            \ |^^^^^^^^| /
              *--|  |--*
                 |  |
                /   \
               *     *
              web complete!
    """,
]


# What Loomy says in each phase of the pipeline
_PHASE_LINES = {
    "init":        "Loomy drops from the silk line, ready to weave...",
    "discover":    "Surveying the code forest for threads to spin...",
    "layers":      "Spinning the analysis web, layer by layer...",
    "taint":       "Tracing tainted threads across files...",
    "cpg":         "Knotting the code property graph...",
    "metamorphic": "Checking each strand for weakness...",
    "aggregate":   "Pulling the silk taut — confidence intervals...",
    "llm":         "Consulting the oracle spider...",
    "autofix":     "Patching the torn strands...",
    "done":        "The web is complete.",
    "warn":        "Loomy felt a vibration — something's caught.",
    "block":       "A strand snapped! This bug is real.",
    "pass":        "The web holds tight. No bugs caught today.",
}


class Mascot:
    """Animated Loomy mascot — a spider weaving a web of analysis.

    v5.9: On terminals that support inline images (Kitty, iTerm2, WezTerm,
    VS Code, Ghostty), Loomy is rendered as a real animated PNG/GIF — crisp
    pixel art with anti-aliasing, not ASCII. Falls back to ASCII art on
    terminals without image protocol support.

    Usage:
        mascot = Mascot()
        mascot.say("init")
        mascot.start_animation()  # background thread
        ... do work ...
        mascot.stop_animation()
        mascot.say("done")

    The animation runs in a daemon thread so it never blocks shutdown.
    """

    def __init__(self, console: Optional["Console"] = None,
                 enabled: bool = True, anim_interval: float = 0.5):
        self.console = console or (Console() if _HAS_RICH else None)
        self.enabled = enabled and _HAS_RICH and sys.stdout.isatty()
        self.anim_interval = anim_interval
        self._anim_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._current_phase = "init"
        self._current_message: Optional[str] = None
        self._frame_idx = 0

        # v5.9: Try to initialize the image renderer for premium graphics
        self._image_mascot = None
        if self.enabled:
            try:
                from .image_render import ImageMascot
                self._image_mascot = ImageMascot(enabled=True,
                                                  anim_interval=0.12)  # ~8fps for GIF
                if not self._image_mascot.supports_images:
                    self._image_mascot = None  # Terminal doesn't support images
            except Exception:
                self._image_mascot = None  # Fall back to ASCII

    # ---------- one-shot rendering ----------

    def say(self, phase: str, message: Optional[str] = None) -> None:
        """Render Loomy in a single frame with a speech bubble.

        Non-animated — for use at stage boundaries.
        v5.9: Uses inline-image rendering (Kitty/iTerm2) when available,
        falls back to ASCII art.
        """
        self._current_phase = phase
        self._current_message = message or _PHASE_LINES.get(phase, "")

        # v5.9: Image path (Kitty/iTerm2/WezTerm/VS Code/Ghostty)
        if self._image_mascot is not None:
            self._image_mascot.say(phase, self._current_message)
            return

        if not self.enabled:
            # Plain-text fallback
            print(f"[loomy] {self._current_message}")
            return
        # For one-shot say(), pick frame based on phase:
        #   init/discover → frame 0
        #   layers/taint/cpg/metamorphic → frames 1-5 (cycling)
        #   aggregate/llm → frame 6
        #   done/warn/block/pass → frame 7
        phase_to_frame = {
            "init": 0, "discover": 0,
            "layers": 2, "taint": 3, "cpg": 4, "metamorphic": 5,
            "aggregate": 6, "llm": 6, "autofix": 6,
            "done": 7, "warn": 7, "block": 7, "pass": 7,
        }
        frame_idx = phase_to_frame.get(phase, 0)
        self._render_frame(frame_idx, with_bubble=True)

    # ---------- background animation ----------

    def start_animation(self, phase: str = "layers",
                        message: Optional[str] = None) -> None:
        """Start the background weaving animation.

        Safe to call multiple times — only one thread runs at a time.
        v5.9: Uses inline-image animation when available.
        """
        # v5.9: Image path
        if self._image_mascot is not None:
            self._image_mascot.start_animation(phase, message or _PHASE_LINES.get(phase, ""))
            return

        if not self.enabled:
            return
        self._current_phase = phase
        self._current_message = message or _PHASE_LINES.get(phase, "")
        if self._anim_thread and self._anim_thread.is_alive():
            return
        self._stop_event.clear()
        self._anim_thread = threading.Thread(
            target=self._animate_loop, daemon=True
        )
        self._anim_thread.start()

    def stop_animation(self) -> None:
        """Stop the background animation and clear the frame."""
        # v5.9: Image path
        if self._image_mascot is not None:
            self._image_mascot.stop_animation()
            return

        if not self.enabled:
            return
        self._stop_event.set()
        if self._anim_thread:
            self._anim_thread.join(timeout=1.0)
        self._anim_thread = None
        # Clear the line where Loomy was animating
        try:
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()
        except Exception:
            pass

    def update_phase(self, phase: str, message: Optional[str] = None) -> None:
        """Update the speech bubble without restarting the animation."""
        self._current_phase = phase
        self._current_message = message or _PHASE_LINES.get(phase, "")
        # v5.9: Also update image mascot's message
        if self._image_mascot is not None:
            self._image_mascot.update_message(self._current_message)

    # ---------- internals ----------

    def _animate_loop(self) -> None:
        """Background loop that cycles through mascot frames."""
        n = len(_MASCOT_FRAMES)
        while not self._stop_event.is_set():
            self._render_frame(self._frame_idx % n, with_bubble=True, clear=True)
            self._frame_idx += 1
            self._stop_event.wait(self.anim_interval)

    def _render_frame(self, idx: int, with_bubble: bool = True,
                      clear: bool = False) -> None:
        """Render one mascot frame with premium multi-color styling.

        v5.10: Uses Rich Text with per-line styling for a premium look:
          - Web strands: dim silver (the web structure)
          - Spider body: bright cyan (the spider itself)
          - Spinneret silk: bright yellow (the active silk)
          - Speech bubble: rounded corners + green text
          - Braille spinner below (like Claude Code's spinner)
        """
        if not self.console:
            return
        frame = _MASCOT_FRAMES[idx % len(_MASCOT_FRAMES)]
        msg = self._current_message or ""

        # Build side-by-side layout: mascot (left) | speech bubble (right)
        mascot_lines = frame.strip("\n").split("\n")
        max_w = max(len(l) for l in mascot_lines)
        mascot_lines = [l.ljust(max_w) for l in mascot_lines]

        # v5.10: Braille spinner (like Claude Code / npm)
        _SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        spinner_char = _SPINNER[idx % len(_SPINNER)]

        if with_bubble and msg:
            # v5.10: Premium rounded speech bubble
            msg_len = len(msg)
            bubble = [
                f"  ╭{'─' * (msg_len + 2)}╮",
                f"  │ {msg} │",
                f"  ╰{'─' * (msg_len + 2)}╯",
            ]
            n_mascot = len(mascot_lines)
            n_bubble = len(bubble)
            offset = max(0, (n_mascot - n_bubble) // 2)
            lines = []
            for i in range(n_mascot):
                left = mascot_lines[i]
                if offset <= i < offset + n_bubble:
                    right = bubble[i - offset]
                else:
                    right = ""
                lines.append(f"{left}  {right}")
            content = "\n".join(lines)
            content += f"\n  {spinner_char} weaving..."
        else:
            content = "\n".join(mascot_lines)

        if clear:
            sys.stdout.write("\033[14A\r\033[J")
            sys.stdout.flush()

        # v5.10: Per-line color styling for premium look
        text = Text()
        for line in content.split("\n"):
            # Determine line type and apply style
            if "╭" in line or "╰" in line or "│" in line:
                # Speech bubble border/text
                text.append_text(Text(line, style="green"))
            elif "weaving" in line:
                # Spinner line
                text.append_text(Text(spinner_char + " ", style="bright_yellow bold"))
                text.append_text(Text("weaving...", style="dim green"))
            elif "~" in line:
                # Spinneret silk
                text.append_text(Text(line, style="bright_yellow"))
            elif any(c in line for c in "()"):
                # Spider body
                text.append_text(Text(line, style="bright_cyan"))
            elif any(c in line for c in "/\\|"):
                # Web strands
                text.append_text(Text(line, style="dim silver"))
            elif "*" in line:
                # Web nodes / dewdrops
                text.append_text(Text(line, style="bright_white"))
            else:
                text.append_text(Text(line, style="dim"))
            text.append("\n")
        # Remove trailing newline
        if text.plain.endswith("\n"):
            text = text[:-1]

        self.console.print(text, end="\r")


# ---------- global singleton ----------

_GLOBAL_MASCOT: Optional[Mascot] = None


def get_global_mascot(enabled: bool = True) -> Mascot:
    """Return the process-wide Mascot singleton.

    This lets the orchestrator and CLI share one mascot instance.
    """
    global _GLOBAL_MASCOT
    if _GLOBAL_MASCOT is None:
        _GLOBAL_MASCOT = Mascot(enabled=enabled)
    return _GLOBAL_MASCOT


def disable_mascot() -> None:
    """Disable the global mascot (e.g. when --no-tui or --quiet is set)."""
    global _GLOBAL_MASCOT
    if _GLOBAL_MASCOT is not None:
        _GLOBAL_MASCOT.stop_animation()
    _GLOBAL_MASCOT = Mascot(enabled=False)


# ============================================================================
# Frame count accessor (for tests)
# ============================================================================

def get_frame_count() -> int:
    """Return the number of frames in the weaving cycle."""
    return len(_MASCOT_FRAMES)


def get_frame(idx: int) -> str:
    """Return a specific frame's ASCII art (for testing)."""
    return _MASCOT_FRAMES[idx % len(_MASCOT_FRAMES)]
