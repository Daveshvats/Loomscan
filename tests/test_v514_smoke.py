"""v5.14 smoke tests — MiMoCode-style redesign.

Covers:
  1. Command palette (Ctrl+P / slash)
  2. Branded header (LOOMSCAN)
  3. Input bar at bottom with orange left border
  4. Status bar (engine, strictness, working directory)
  5. Single-screen layout (content area swaps, header/input/footer fixed)
  6. Working directory changeable via 'cd' command
  7. Engine changeable via 'engine' command
  8. ScanView and ResultsView widgets
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def test_version_514():
    """v5.14+: version must be >= 5.14.0."""
    import loomscan
    v = tuple(int(x) for x in loomscan.__version__.split("."))
    assert v[0] >= 7 or v >= (5, 14, 0)


def test_pyproject_514():
    """v5.14+: pyproject.toml must match __version__."""
    import loomscan
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    assert f'version = "{loomscan.__version__}"' in pyproject.read_text()


# ============================================================================

def test_command_palette_exists():
    """v5.14: CommandPalette class must exist."""
    pytest.importorskip("textual")
    from loomscan.tui.app import CommandPalette
    assert CommandPalette is not None


def test_command_palette_has_commands():
    """v5.14+: CommandPalette must have commands."""
    pytest.importorskip("textual")
    try:
        from loomscan.tui.command_palette import CommandPalette, COMMANDS
        assert len(COMMANDS) >= 5
        cmd_ids = [c.cmd_id for c in COMMANDS]
        assert "scan" in cmd_ids
        assert "results" in cmd_ids
        assert "quit" in cmd_ids
    except ImportError:
        from loomscan.tui.app import CommandPalette
        assert hasattr(CommandPalette, 'COMMANDS')


def test_app_has_branded_header():
    """v5.14+: App must have a branded header/logo."""
    pytest.importorskip("textual")
    import inspect
    from loomscan.tui.app import LoomScanApp
    source = inspect.getsource(LoomScanApp.compose)
    # v5.15 uses #logo-text with ASCII art; v5.14 used #app-header
    assert "logo" in source or "app-header" in source, "App missing logo/header"


def test_app_has_input_bar():
    """v5.14+: App must have an input bar."""
    pytest.importorskip("textual")
    import inspect
    from loomscan.tui.app import LoomScanApp
    source = inspect.getsource(LoomScanApp.compose)
    assert "main-input" in source, "App missing #main-input Input widget"


def test_app_has_status_bar():
    """v5.14: App must have a status bar (#status-bar)."""
    pytest.importorskip("textual")
    import inspect
    from loomscan.tui.app import LoomScanApp
    source = inspect.getsource(LoomScanApp.compose)
    assert "status-bar" in source, "App missing #status-bar"


def test_app_has_content_area():
    """v5.14: App must have a content area (#content-area)."""
    pytest.importorskip("textual")
    import inspect
    from loomscan.tui.app import LoomScanApp
    source = inspect.getsource(LoomScanApp.compose)
    assert "content-area" in source, "App missing #content-area"


def test_app_has_footer():
    """v5.14: App must have a Footer widget."""
    pytest.importorskip("textual")
    import inspect
    from loomscan.tui.app import LoomScanApp
    source = inspect.getsource(LoomScanApp.compose)
    assert "Footer" in source, "App missing Footer widget"


def test_app_supports_slash_commands():
    """v5.14+: App must handle slash (/) for command palette."""
    pytest.importorskip("textual")
    from loomscan.tui.app import LoomScanApp
    has_slash = False
    for binding in LoomScanApp.BINDINGS:
        if "/" in binding.key or "slash" in binding.key:
            has_slash = True
            break
    assert has_slash, "'/' not bound to command palette"


def test_app_supports_ctrl_p():
    """v5.14: App must handle Ctrl+P for command palette."""
    pytest.importorskip("textual")
    from loomscan.tui.app import LoomScanApp
    has_ctrl_p = False
    for binding in LoomScanApp.BINDINGS:
        if "ctrl+p" in binding.key:
            has_ctrl_p = True
            break
    assert has_ctrl_p, "Ctrl+P not bound to command palette"


def test_app_handles_cd_command():
    """v5.14+: App must handle 'cd <path>'."""
    pytest.importorskip("textual")
    import inspect
    from loomscan.tui.app import LoomScanApp
    source = inspect.getsource(LoomScanApp._handle_command)
    assert "cd" in source or "_change_dir" in source, "App doesn't handle 'cd'"


def test_app_handles_engine_command():
    """v5.14+: App must handle 'engine <choice>'."""
    pytest.importorskip("textual")
    import inspect
    from loomscan.tui.app import LoomScanApp
    source = inspect.getsource(LoomScanApp._handle_command)
    assert "engine" in source, "App doesn't handle 'engine' command"


def test_scan_view_exists():
    """v5.14: ScanView widget must exist."""
    pytest.importorskip("textual")
    from loomscan.tui.scan_view import ScanView
    assert ScanView is not None


def test_results_view_exists():
    """v5.14: ResultsView widget must exist."""
    pytest.importorskip("textual")
    from loomscan.tui.results_view import ResultsView
    assert ResultsView is not None


def test_app_css_has_dark_theme():
    """v5.14: App CSS must use dark theme (#0a0a0a background)."""
    pytest.importorskip("textual")
    from loomscan.tui.app import LoomScanApp
    assert "#0a0a0a" in LoomScanApp.CSS, "App CSS missing dark background"
    assert "$accent" in LoomScanApp.CSS, "App CSS missing accent color"


def test_app_css_has_input_bar_styling():
    """v5.14+: App CSS must style the input bar."""
    pytest.importorskip("textual")
    from loomscan.tui.app import LoomScanApp
    assert "#main-input" in LoomScanApp.CSS or "#input-bar" in LoomScanApp.CSS,         "CSS missing input bar styling"


# ============================================================================
# Regression: v5.13 features still work
# ============================================================================

def test_v513_no_text_size():
    """v5.14: v5.13 fix (no text-size) must still hold."""
    tui_dir = Path(__file__).resolve().parent.parent / "loomscan" / "tui"
    for py_file in tui_dir.rglob("*.py"):
        content = py_file.read_text()
        assert "text-size:" not in content, (
            f"{py_file.name} has 'text-size:' CSS property (invalid)"
        )


def test_v513_cwe_map():
    """v5.14: v5.12 CWE map must still exist."""
    from loomscan.orchestrator import _SINK_TYPE_CWE_MAP
    assert len(_SINK_TYPE_CWE_MAP) >= 10


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
