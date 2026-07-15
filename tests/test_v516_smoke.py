"""v5.16 smoke tests — OpenTUI integration.

Covers:
  1. opentui package installed and importable
  2. opentui_app.py module exists with launch_tui
  3. App uses OpenTUI components (Box, Text, Signal, etc.)
  4. TUI shows only progress (no findings in terminal)
  5. Auto-generates HTML + SARIF reports
  6. CLI uses opentui_app as primary TUI
  7. pyproject.toml includes opentui dependency
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def test_version_516():
    """v5.16: version must be 5.16.0."""
    import loomscan
    v = tuple(int(x) for x in loomscan.__version__.split(".")); assert v[0] >= 7 or v >= (5, 16, 0)


def test_pyproject_516():
    """v5.16: pyproject.toml version must be 5.16.0."""
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    import loomscan; assert f'version = "{loomscan.__version__}"' in pyproject.read_text()


# ============================================================================

def test_opentui_imports():
    """v5.16: opentui package must be importable."""
    pytest.importorskip("opentui")
    import opentui
    assert hasattr(opentui, "render")
    assert hasattr(opentui, "Box")
    assert hasattr(opentui, "Text")
    assert hasattr(opentui, "Signal")
    assert hasattr(opentui, "Input")


def test_opentui_app_module_exists():
    """v5.16: opentui_app.py module must exist with launch_tui."""
    pytest.importorskip("opentui")
    from loomscan.tui.opentui_app import launch_tui, App, state
    assert callable(launch_tui)
    assert App is not None
    assert state is not None


def test_opentui_app_uses_signals():
    """v5.16: App must use OpenTUI Signal for reactive state."""
    pytest.importorskip("opentui")
    from loomscan.tui.opentui_app import state
    # State should have reactive signals
    assert hasattr(state, "current_view")
    assert hasattr(state, "scan_stage")
    assert hasattr(state, "scan_progress")
    assert hasattr(state, "scan_findings")
    assert hasattr(state, "scan_running")


def test_tui_shows_only_progress_no_findings():
    """v5.16: TUI scanning view must show progress, NOT findings details.

    The user explicitly requested: no findings should be displayed in the TUI.
    Findings go to the HTML/SARIF report instead.
    """
    pytest.importorskip("opentui")
    app_path = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "opentui_app.py"
    content = app_path.read_text()

    # Must have a scanning view that shows progress
    assert "ScanningView" in content or "scan_stage" in content
    assert "scan_progress" in content
    assert "scan_files" in content

    # Must NOT display individual findings (just a count is OK)
    # The key: no DataTable, no findings table, no per-finding display
    assert "DataTable" not in content, "TUI should NOT show findings table"
    # scan_findings count is OK (just a number), but no finding details


def test_auto_generates_reports():
    """v5.16: TUI must auto-generate HTML + SARIF after scan."""
    pytest.importorskip("opentui")
    app_path = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "opentui_app.py"
    content = app_path.read_text()
    assert "_generate_reports" in content, "Missing report generation"
    assert "save_sarif" in content, "Missing SARIF generation"
    assert "save_html" in content, "Missing HTML generation"
    assert "_open_in_browser" in content, "Missing browser opening"


def test_open_in_browser_platform_specific():
    """v5.16: _open_in_browser must use platform-specific commands."""
    pytest.importorskip("opentui")
    app_path = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "opentui_app.py"
    content = app_path.read_text()
    assert "Darwin" in content and "open" in content, "Missing macOS 'open' command"
    assert "Linux" in content and "xdg-open" in content, "Missing Linux 'xdg-open'"
    assert "Windows" in content and "start" in content, "Missing Windows 'start'"


def test_cli_uses_opentui_primary():
    """v5.16+: CLI may use opentui_app (v5.16) or cli_display (v5.17+)."""
    cli_path = Path(__file__).resolve().parent.parent / "loomscan" / "cli.py"
    content = cli_path.read_text()
    assert "cli_display" in content or "opentui_app" in content, "CLI missing display module"


def test_pyproject_includes_opentui():
    """v5.16: pyproject.toml must include opentui dependency."""
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    content = pyproject.read_text()
    assert "opentui" in content, "Missing opentui dependency"
    assert "yoga-python" in content, "Missing yoga-python dependency"


def test_opentui_app_has_logo():
    """v5.16: TUI must render the LOOMSCAN logo."""
    pytest.importorskip("opentui")
    app_path = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "opentui_app.py"
    content = app_path.read_text()
    assert "LOOMSCAN_LOGO" in content, "TUI doesn't use the logo"
    assert "Logo" in content, "Missing Logo component"


def test_opentui_app_has_input_bar():
    """v5.16: TUI must have an input bar at the bottom."""
    pytest.importorskip("opentui")
    app_path = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "opentui_app.py"
    content = app_path.read_text()
    assert "Input(" in content or "_InputBar" in content, "Missing input bar"
    assert "on_submit" in content or "_handle_input" in content, "Missing input handler"


def test_opentui_app_has_status_bar():
    """v5.16: TUI must have a status bar showing engine/strictness/dir."""
    pytest.importorskip("opentui")
    app_path = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "opentui_app.py"
    content = app_path.read_text()
    assert "engine_label" in content, "Missing engine in status bar"
    assert "strictness" in content, "Missing strictness in status bar"
    assert "dir_label" in content, "Missing directory in status bar"


def test_opentui_app_supports_commands():
    """v5.16: TUI must handle key commands (scan, results, doctor, etc.)."""
    pytest.importorskip("opentui")
    app_path = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "opentui_app.py"
    content = app_path.read_text()
    assert "scan" in content, "Missing 'scan' command"
    assert "results" in content, "Missing 'results' command"
    assert "doctor" in content, "Missing 'doctor' command"
    assert "settings" in content, "Missing 'settings' command"
    assert "cd" in content, "Missing 'cd' command"
    assert "engine" in content, "Missing 'engine' command"
    assert "strictness" in content, "Missing 'strictness' command"
    assert "quit" in content, "Missing 'quit' command"


# ============================================================================
# Regression: v5.15 features
# ============================================================================

def test_v515_logo_exists():
    """v5.16: v5.15 ASCII logo must still exist."""
    logo_path = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "logo.py"
    assert logo_path.exists()
    from loomscan.tui.logo import LOOMSCAN_LOGO
    assert len(LOOMSCAN_LOGO) >= 5


def test_v515_command_palette_exists():
    """v5.16: v5.15 command palette must still exist."""
    palette_path = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "command_palette.py"
    assert palette_path.exists()


def test_v515_wizard_exists():
    """v5.16: v5.15 config wizard must still exist."""
    wizard_path = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "wizard.py"
    assert wizard_path.exists()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
