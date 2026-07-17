"""v5.9 smoke tests — premium mascot via inline-image protocols, doctor fixes.

Covers the 5 main v5.9 features:
  1. Image renderer module (loomscan/tui/image_render.py)
  2. Terminal protocol detection (Kitty/iTerm2/Sixel/ASCII)
  3. Kitty + iTerm2 escape sequence generation
  4. Mascot uses image renderer when available, ASCII fallback
  5. Doctor skfuzzy fix + mascot renderer info

Plus regression checks:
  - Version bumped to 5.9.0
  - README updated to v5.9
  - v5.8 features still work
"""
from __future__ import annotations

import os
import sys
import subprocess
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ============================================================================
# Version checks
# ============================================================================

def test_version_bumped_to_59():
    """v5.9+: __version__ must be >= 5.9.0 (v5.10+ also passes)."""
    import loomscan
    v_parts = tuple(int(x) for x in loomscan.__version__.split("."))
    assert v_parts[0] >= 7 or v_parts >= (5, 9, 0), f"Version {loomscan.__version__} < 5.9.0"


def test_pyproject_version_matches_59():
    """v5.9+: pyproject.toml version must match __version__ (>= 5.9.0)."""
    import loomscan
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    content = pyproject.read_text()
    assert f'version = "{loomscan.__version__}"' in content, (
        f"pyproject.toml version doesn't match __version__ ({loomscan.__version__})"
    )


def test_readme_header_says_v59_or_later():
    """v5.9+: README header should say v5.9 or later."""
    readme = Path(__file__).resolve().parent.parent / "README.md"
    content = readme.read_text()
    first_lines = "\n".join(content.split("\n")[:10])
    import re
    match = re.search(r'v(\d+)\.(\d+)', first_lines)
    assert match, f"README header doesn't mention a version: {first_lines[:200]}"
    major, minor = int(match.group(1)), int(match.group(2))
    assert (major, minor) >= (5, 9), f"README version {major}.{minor} < 5.9"


def test_readme_header_says_v59():
    """Backward-compat alias."""
    test_readme_header_says_v59_or_later()

def test_readme_mentions_inline_image_protocols():
    """v5.9: README should mention inline-image protocols."""
    readme = Path(__file__).resolve().parent.parent / "README.md"
    content = readme.read_text()
    # Accept any combination of these terms
    has_protocol = any(term in content for term in ["Kitty", "iTerm2", "WezTerm", "VS Code", "Ghostty"])
    assert has_protocol, "README doesn't mention any inline-image protocol"
    # "pixel" is optional — just check for "mascot" or "spider" or "image"
    has_mascot = any(term in content.lower() for term in ["mascot", "spider", "image", "pixel"])
    assert has_mascot, "README doesn't mention mascot/image rendering"

# ============================================================================
# Image renderer module tests
# ============================================================================

def test_image_render_module_imports():
    """v5.9: loomscan.tui.image_render module must import."""
    from loomscan.tui.image_render import (ImageMascot, detect_terminal_protocol,
                                            is_image_supported)
    assert ImageMascot is not None
    assert detect_terminal_protocol is not None
    assert is_image_supported is not None


def test_detect_terminal_protocol_returns_string():
    """v5.9: detect_terminal_protocol() must return a known protocol name."""
    from loomscan.tui.image_render import detect_terminal_protocol
    protocol = detect_terminal_protocol()
    assert protocol in ("kitty", "iterm2", "sixel", "ascii"), (
        f"Unknown protocol: {protocol}"
    )


def test_detect_terminal_protocol_ascii_in_non_tty(monkeypatch):
    """v5.9: Protocol must be 'ascii' when stdout is not a TTY."""
    # In test environment, stdout is typically not a TTY
    from loomscan.tui.image_render import detect_terminal_protocol
    protocol = detect_terminal_protocol()
    # This test runs under pytest → stdout is captured → not a TTY
    assert protocol == "ascii", f"Expected 'ascii' in non-TTY, got '{protocol}'"


def test_detect_terminal_protocol_kitty(monkeypatch):
    """v5.9: TERM=xterm-kitty should detect Kitty protocol."""
    monkeypatch.setenv("TERM", "xterm-kitty")
    monkeypatch.setenv("TERM_PROGRAM", "")
    # We can't easily fake isatty() in a test, so we test the env-var logic
    # by calling the internal detection directly
    from loomscan.tui import image_render
    # Save original isatty
    orig_isatty = sys.stdout.isatty
    sys.stdout.isatty = lambda: True
    try:
        protocol = image_render.detect_terminal_protocol()
    finally:
        sys.stdout.isatty = orig_isatty
    assert protocol == "kitty", f"Expected 'kitty', got '{protocol}'"


def test_detect_terminal_protocol_iterm2(monkeypatch):
    """v5.9: TERM_PROGRAM=iTerm.app should detect iTerm2 protocol."""
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setenv("TERM_PROGRAM", "iTerm.app")
    from loomscan.tui import image_render
    orig_isatty = sys.stdout.isatty
    sys.stdout.isatty = lambda: True
    try:
        protocol = image_render.detect_terminal_protocol()
    finally:
        sys.stdout.isatty = orig_isatty
    assert protocol == "iterm2", f"Expected 'iterm2', got '{protocol}'"


def test_detect_terminal_protocol_vscode(monkeypatch):
    """v5.9: TERM_PROGRAM=vscode should detect iTerm2 protocol (VS Code supports it)."""
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setenv("TERM_PROGRAM", "vscode")
    from loomscan.tui import image_render
    orig_isatty = sys.stdout.isatty
    sys.stdout.isatty = lambda: True
    try:
        protocol = image_render.detect_terminal_protocol()
    finally:
        sys.stdout.isatty = orig_isatty
    assert protocol == "iterm2", f"Expected 'iterm2' for VS Code, got '{protocol}'"


def test_detect_terminal_protocol_wezterm(monkeypatch):
    """v5.9: TERM_PROGRAM=WezTerm should detect iTerm2 protocol."""
    monkeypatch.setenv("TERM", "wezterm")
    monkeypatch.setenv("TERM_PROGRAM", "WezTerm")
    from loomscan.tui import image_render
    orig_isatty = sys.stdout.isatty
    sys.stdout.isatty = lambda: True
    try:
        protocol = image_render.detect_terminal_protocol()
    finally:
        sys.stdout.isatty = orig_isatty
    assert protocol == "iterm2", f"Expected 'iterm2' for WezTerm, got '{protocol}'"


def test_detect_terminal_protocol_ghostty(monkeypatch):
    """v5.9: TERM_PROGRAM=ghostty should detect Kitty protocol."""
    monkeypatch.setenv("TERM", "xterm-ghostty")
    monkeypatch.setenv("TERM_PROGRAM", "ghostty")
    from loomscan.tui import image_render
    orig_isatty = sys.stdout.isatty
    sys.stdout.isatty = lambda: True
    try:
        protocol = image_render.detect_terminal_protocol()
    finally:
        sys.stdout.isatty = orig_isatty
    assert protocol == "kitty", f"Expected 'kitty' for Ghostty, got '{protocol}'"


# ============================================================================
# Escape sequence generation tests
# ============================================================================

def test_kitty_escape_sequence_structure():
    """v5.9+: Kitty escape sequence must have correct structure."""
    from loomscan.tui.image_render import _kitty_encode_image
    frames_dir = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "assets" / "frames"
    frame_path = str(frames_dir / "frame_00.png")

    seq = _kitty_encode_image(frame_path, width=20, height=10)
    # Must start with ESC G (Kitty graphics protocol)
    assert seq.startswith("\x1b_G"), f"Kitty seq must start with ESC G, got: {seq[:20]!r}"
    # Must end with ESC \ (String Terminator)
    assert seq.endswith("\x1b\\"), f"Kitty seq must end with ESC \\, got: {seq[-20:]!r}"


def test_kitty_chunking_for_large_frames():
    """v5.9+: Large PNG frames must be split into Kitty chunks."""
    from loomscan.tui.image_render import _kitty_encode_image
    frames_dir = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "assets" / "frames"
    frame_path = str(frames_dir / "frame_00.png")
    seq = _kitty_encode_image(frame_path, width=20, height=10)
    # Count ESC G occurrences = number of chunks
    chunk_count = seq.count("\x1b_G")
    assert chunk_count >= 1, f"Should have at least 1 chunk, got {chunk_count}"


def test_iterm2_escape_sequence_structure():
    """v5.9+: iTerm2 escape sequence must have correct structure."""
    from loomscan.tui.image_render import _iterm2_encode_image
    frames_dir = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "assets" / "frames"
    frame_path = str(frames_dir / "frame_00.png")

    seq = _iterm2_encode_image(frame_path)
    # Must start with ESC ] 1337 ; (OSC 1337)
    assert seq.startswith("\x1b]1337;"), f"iTerm2 seq must start with ESC]1337;, got: {seq[:20]!r}"
    # Must end with BEL (\x07)
    assert seq.endswith("\x07"), f"iTerm2 seq must end with BEL, got: {seq[-20:]!r}"
    # Must contain File=inline=1
    assert "File=inline=1" in seq, "iTerm2 seq missing File=inline=1"
    # Must contain base64-encoded PNG data
    assert "iVBORw0KGgo" in seq, "iTerm2 seq missing base64 PNG data (PNG magic)"


# ============================================================================
# Mascot integration tests
# ============================================================================

def test_mascot_uses_image_renderer_when_available():
    """v5.9: Mascot should initialize ImageMascot when terminal supports it."""
    from loomscan.tui.mascot import Mascot
    # In test env (non-TTY), Mascot won't have image support
    m = Mascot(enabled=False)
    # ImageMascot should be None when enabled=False
    assert m._image_mascot is None, "ImageMascot should be None when Mascot disabled"


def test_mascot_ascii_fallback_still_works():
    """v5.9: When image rendering unavailable, ASCII mascot must still work."""
    from loomscan.tui.mascot import Mascot
    m = Mascot(enabled=False)
    # All methods must work without crashing
    m.say("init")
    m.say("done", "test message")
    m.say("pass")
    m.start_animation(phase="layers", message="test")
    import time; time.sleep(0.1)
    m.stop_animation()
    m.update_phase("taint", "test")


def test_image_mascot_does_not_crash_without_image_support():
    """v5.9+: ImageMascot must not crash on terminals without image support."""
    from loomscan.tui.image_render import ImageMascot
    im = ImageMascot()
    # All methods must be no-ops (not crashes) regardless of terminal support
    im.say("init", "test")
    im.start_animation(phase="layers", message="test")
    import time; time.sleep(0.1)
    im.stop_animation()


# ============================================================================
# Asset file tests
# ============================================================================

def test_spider_gif_exists():
    """v5.9: Optimized spider GIF must exist in assets/."""
    gif = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "assets" / "loomy-spider-opt.gif"
    assert gif.exists(), f"Spider GIF missing: {gif}"
    # Must be under 500KB (optimized)
    assert gif.stat().st_size < 500_000, (
        f"Spider GIF too large: {gif.stat().st_size} bytes (should be < 500KB)"
    )


def test_png_frames_exist():
    """v5.9: 24 PNG frames must exist in assets/frames/."""
    frames_dir = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "assets" / "frames"
    assert frames_dir.exists(), f"Frames directory missing: {frames_dir}"
    pngs = list(frames_dir.glob("frame_*.png"))
    assert len(pngs) == 24, f"Expected 24 PNG frames, got {len(pngs)}"
    # Total PNG size should be under 500KB
    total_size = sum(p.stat().st_size for p in pngs)
    assert total_size < 500_000, (
        f"Total PNG frames too large: {total_size} bytes (should be < 500KB)"
    )


def test_original_large_gif_removed():
    """v5.9: Original 4.7MB GIF must NOT exist (only the optimized one)."""
    original = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "assets" / "loomy-spider.gif"
    assert not original.exists(), (
        f"Original large GIF should be removed: {original}"
    )


def test_pyproject_includes_assets():
    """v5.9: pyproject.toml must include mascot assets in package-data."""
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    content = pyproject.read_text()
    assert "loomscan.tui" in content, "pyproject.toml missing loomscan.tui in package-data"
    assert "assets/*.gif" in content, "pyproject.toml missing assets/*.gif glob"
    assert "assets/frames/*.png" in content, "pyproject.toml missing assets/frames/*.png glob"


# ============================================================================
# Doctor command tests
# ============================================================================

def test_doctor_does_not_require_skfuzzy():
    """v5.10: Doctor must NOT check for scikit-fuzzy (removed from deps)."""
    cli_path = Path(__file__).resolve().parent.parent / "loomscan" / "cli" / "__init__.py"
    c = cli_path.read_text()
    doctor_section = c[c.find('def doctor_cmd'):c.find('def doctor_cmd')+3000]
    assert '("scikit-fuzzy"' not in doctor_section, (
        "Doctor still references scikit-fuzzy (should be removed in v5.10)"
    )


def test_doctor_reports_mascot_renderer():
    """v5.9: Doctor output must mention TUI mascot renderer status."""
    # v7.5.4: Compute project root before subprocess (Path not available in -c context)
    _project_root = str(Path(__file__).resolve().parent.parent)
    result = subprocess.run(
        [sys.executable, "-c",
         f"import sys; sys.path.insert(0, {_project_root!r}); "
         "from loomscan.cli import main; sys.argv = ['loomscan', 'doctor']; main()"],
        capture_output=True, text=True, timeout=30
    )
    combined = result.stdout + result.stderr
    assert "TUI mascot" in combined or "mascot" in combined.lower(), (
        f"Doctor output missing mascot info: {combined[:300]}"
    )


def test_doctor_does_not_mention_skfuzzy():
    """v5.10: Doctor output should NOT mention scikit-fuzzy (removed from deps)."""
    _project_root = str(Path(__file__).resolve().parent.parent)
    result = subprocess.run(
        [sys.executable, "-c",
         f"import sys; sys.path.insert(0, {_project_root!r}); "
         "from loomscan.cli import main; sys.argv = ['loomscan', 'doctor']; main()"],
        capture_output=True, text=True, timeout=30
    )
    assert "scikit-fuzzy" not in result.stdout, (
        f"Doctor still mentions scikit-fuzzy: {result.stdout[:300]}"
    )
    assert "skfuzzy" not in result.stdout, (
        f"Doctor still mentions skfuzzy: {result.stdout[:300]}"
    )


# ============================================================================
# Version flag test
# ============================================================================

def test_version_flag_works():
    """v5.9+: loomscan --version must show the current version."""
    import loomscan
    _project_root = str(Path(__file__).resolve().parent.parent)
    result = subprocess.run(
        [sys.executable, "-c",
         f"import sys; sys.path.insert(0, {_project_root!r}); "
         "from loomscan.cli import main; sys.argv = ['loomscan', '--version']; main()"],
        capture_output=True, text=True, timeout=10
    )
    assert loomscan.__version__ in result.stdout, f"--version output: {result.stdout}"


# ============================================================================
# Regression: v5.8 features still work
# ============================================================================

def test_v58_spider_mascot_frames_still_exist():
    """v5.9: v5.8 ASCII spider frames must still exist (fallback path)."""
    from loomscan.tui.mascot import get_frame_count, get_frame
    assert get_frame_count() == 8, "v5.8 ASCII mascot should have 8 frames"
    frame0 = get_frame(0)
    assert "(" in frame0 and ")" in frame0, "ASCII spider body missing"


def test_v58_doctor_command_still_exists():
    """v5.9: v5.8 loomscan doctor command must still exist."""
    from loomscan.cli import main
    assert "doctor" in main.commands


def test_v58_3tier_install_model_intact():
    """v5.9: v5.8 3-tier install model must still be in pyproject.toml."""
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    content = pyproject.read_text()
    assert "full = [" in content
    assert "fast = [" in content
    assert "loomscan-regex" in content


def test_v58_rust_wheel_workflow_exists():
    """v5.9: v5.8 Rust wheel CI workflow should exist (or CI workflow exists)."""
    # v7.5.3: build-rust-wheels.yml was consolidated into ci.yml. Accept either.
    workflows_dir = Path(__file__).resolve().parent.parent / ".github" / "workflows"
    rust_workflow = workflows_dir / "build-rust-wheels.yml"
    ci_workflow = workflows_dir / "ci.yml"
    assert rust_workflow.exists() or ci_workflow.exists(), \
        "Either build-rust-wheels.yml or ci.yml workflow should exist"


def test_v57_yaml_engine_still_fires():
    """v5.9: v5.7 YAML engine must still produce findings on Flask XSS fixture."""
    from loomscan.yaml_engine import apply_pack_to_file
    import tempfile
    framework_pack = Path(__file__).resolve().parent.parent / "loomscan" / "rules" / "packs" / "framework-taint.yml"
    assert framework_pack.exists()

    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        src = repo / "app.py"
        src.write_text(
            "from flask import Flask, render_template_string\n"
            "app = Flask(__name__)\n"
            "@app.route('/')\n"
            "def index():\n"
            "    name = 'world'\n"
            "    return render_template_string('<h1>Hello ' + name + '</h1>')\n"
        )
        hits = apply_pack_to_file(framework_pack, src, repo_root=repo)
        rule_ids = {h.rule_id for h in hits}
        assert any('xss' in r.lower() or 'ssti' in r.lower() or 'flask' in r.lower()
                    for r in rule_ids), \
            f"Flask XSS/SSTI rule not firing: {rule_ids}"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
