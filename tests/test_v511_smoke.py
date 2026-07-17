"""v5.11 smoke tests — Textual TUI app, mascot widget, two-mode CLI.

Covers:
  1. TUI app module imports
  2. All 5 screens (welcome, config, scanning, results, settings) exist
  3. Mascot widget with 3-tier rendering (image/ascii/none)
  4. CLI launches TUI when no args + TTY
  5. CLI falls back to help when no args + non-TTY
  6. Existing CLI commands still work (check, --version, etc.)
  7. pyproject.toml has [tui] extra + Python 3.12+ requirement
  8. ASCII spider art is bundled as asset
"""
from __future__ import annotations

import sys
import subprocess
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ============================================================================
# Version checks
# ============================================================================

def test_version_bumped_to_511():
    """v5.11+: __version__ must be >= 5.11.0 (v5.12+ also passes)."""
    import loomscan
    v_parts = tuple(int(x) for x in loomscan.__version__.split("."))
    assert v_parts[0] >= 7 or v_parts >= (5, 11, 0), f"Version {loomscan.__version__} < 5.11.0"


def test_pyproject_version_511():
    """v5.11+: pyproject.toml version must match __version__ (>= 5.11.0)."""
    import loomscan
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    content = pyproject.read_text()
    assert f'version = "{loomscan.__version__}"' in content


def test_pyproject_requires_python_312():
    """v5.11: pyproject.toml must require Python >= 3.12 (for textual-image)."""
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    content = pyproject.read_text()
    assert 'requires-python = ">=3.12"' in content


def test_readme_mentions_v511():
    """v5.11: README should mention v5.11."""
    readme = Path(__file__).resolve().parent.parent / "README.md"
    content = readme.read_text()
    # README header should mention v5.11 or v5.10+
    import re
    match = re.search(r'v(\d+)\.(\d+)', content[:500])
    assert match, "README doesn't mention a version"
    major, minor = int(match.group(1)), int(match.group(2))
    assert (major, minor) >= (5, 10), f"README version {major}.{minor} < 5.10"


# ============================================================================
# TUI app module tests
# ============================================================================

def test_tui_app_module_imports():
    """v5.11: loomscan.tui.app module must import."""
    pytest.importorskip("textual")
    from loomscan.tui.app import LoomScanApp, launch_tui
    assert LoomScanApp is not None
    assert callable(launch_tui)


def test_tui_app_has_5_modes():
    """v5.11+: LoomScanApp may have 5 modes (v5.11-5.13) or single-screen (v5.14+)."""
    pytest.importorskip("textual")
    from loomscan.tui.app import LoomScanApp
    app = LoomScanApp()
    # v5.14 changed to single-screen layout — MODES may be empty
    if hasattr(app, 'MODES') and app.MODES:
        expected_modes = {"welcome", "config", "scanning", "results", "settings"}
        assert set(app.MODES.keys()) == expected_modes
    # If no MODES, that's fine — v5.14+ uses content-area swapping


def test_tui_screens_import():
    """v5.11: All 5 screen classes must import."""
    pytest.importorskip("textual")
    from loomscan.tui.screens import (
        WelcomeScreen, ConfigScreen, ScanningScreen,
        ResultsScreen, SettingsScreen
    )
    assert WelcomeScreen is not None
    assert ConfigScreen is not None
    assert ScanningScreen is not None
    assert ResultsScreen is not None
    assert SettingsScreen is not None


# ============================================================================
# Mascot widget tests
# ============================================================================

def test_mascot_widget_imports():
    """v5.11: MascotWidget must import."""
    pytest.importorskip("textual")
    from loomscan.tui.mascot_widget import MascotWidget
    assert MascotWidget is not None


def test_mascot_widget_ascii_art_exists():
    """v5.11: ASCII spider art must exist in assets."""
    art_path = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "assets" / "loomy-spider-ascii.txt"
    assert art_path.exists(), f"ASCII spider art missing: {art_path}"
    content = art_path.read_text()
    # Must be non-trivial art (at least 20 lines)
    assert len(content.strip().split("\n")) >= 20, (
        f"ASCII art too short: {len(content.strip().split(chr(10)))} lines"
    )


def test_mascot_widget_png_frames_exist():
    """v5.11: 24 PNG frames must still exist for image-mode terminals."""
    frames_dir = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "assets" / "frames"
    assert frames_dir.exists()
    pngs = list(frames_dir.glob("frame_*.png"))
    assert len(pngs) == 24, f"Expected 24 PNG frames, got {len(pngs)}"


def test_mascot_widget_image_detection():
    """v5.11: _detect_image_support() must return a bool."""
    pytest.importorskip("textual")
    from loomscan.tui.mascot_widget import _detect_image_support
    result = _detect_image_support()
    assert isinstance(result, bool)


# ============================================================================
# CLI two-mode tests
# ============================================================================

def test_cli_version_still_works():
    """v5.11: loomscan --version must still work (CLI mode)."""
    _project_root = str(Path(__file__).resolve().parent.parent)
    result = subprocess.run(
        [sys.executable, "-c",
         f"import sys; sys.path.insert(0, {_project_root!r}); "
         "from loomscan.cli import main; sys.argv = ['loomscan', '--version']; main()"],
        capture_output=True, text=True, timeout=10
    )
    import loomscan
    assert loomscan.__version__ in result.stdout


def test_cli_help_shows_when_no_args_non_tty():
    """v5.11: loomscan (no args) in non-TTY must show help, not crash."""
    _project_root = str(Path(__file__).resolve().parent.parent)
    result = subprocess.run(
        [sys.executable, "-c",
         f"import sys; sys.path.insert(0, {_project_root!r}); "
         "from loomscan.cli import main; sys.argv = ['loomscan']; main()"],
        capture_output=True, text=True, timeout=10
    )
    # Non-TTY → should show help (exit 0)
    assert result.returncode == 0
    assert "LoomScan" in result.stdout or "Usage" in result.stdout


def test_cli_check_command_still_works():
    """v5.11: loomscan check command must still exist and work."""
    from loomscan.cli import main
    assert "check" in main.commands


def test_cli_quickstart_still_exists():
    """v5.11: loomscan quickstart command must still exist."""
    from loomscan.cli import main
    assert "quickstart" in main.commands


def test_cli_doctor_still_exists():
    """v5.11: loomscan doctor command must still exist."""
    from loomscan.cli import main
    assert "doctor" in main.commands


# ============================================================================
# pyproject.toml tests
# ============================================================================

def test_pyproject_has_tui_extra():
    """v5.11: pyproject.toml must have [tui] extra with textual deps."""
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    content = pyproject.read_text()
    assert 'tui = [' in content, "Missing [tui] extra"
    assert "textual" in content, "Missing textual dependency"
    assert "textual-image" in content, "Missing textual-image dependency"
    assert "textual-fspicker" in content, "Missing textual-fspicker dependency"


def test_pyproject_includes_ascii_art_in_package_data():
    """v5.11: pyproject.toml must include *.txt in tui assets (ASCII art)."""
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    content = pyproject.read_text()
    assert 'assets/*.txt' in content, "ASCII art (*.txt) not in package-data"


# ============================================================================
# TUI screen structure tests
# ============================================================================

def test_welcome_screen_has_mascot():
    """v5.11: WelcomeScreen must compose a MascotWidget."""
    pytest.importorskip("textual")
    from loomscan.tui.screens.welcome import WelcomeScreen
    # Check the source contains MascotWidget reference
    import inspect
    source = inspect.getsource(WelcomeScreen)
    assert "MascotWidget" in source, "WelcomeScreen doesn't use MascotWidget"


def test_config_screen_has_checkboxes():
    """v5.11: ConfigScreen must use checkboxes (not CLI flags)."""
    pytest.importorskip("textual")
    from loomscan.tui.screens.config import ConfigScreen
    import inspect
    source = inspect.getsource(ConfigScreen)
    assert "Checkbox" in source, "ConfigScreen doesn't use Checkbox widgets"


def test_results_screen_has_datatable():
    """v5.11: ResultsScreen must use DataTable for scrollable results."""
    pytest.importorskip("textual")
    from loomscan.tui.screens.results import ResultsScreen
    import inspect
    source = inspect.getsource(ResultsScreen)
    assert "DataTable" in source, "ResultsScreen doesn't use DataTable"


def test_scanning_screen_has_progress_and_log():
    """v5.11: ScanningScreen must have ProgressBar + RichLog."""
    pytest.importorskip("textual")
    from loomscan.tui.screens.scanning import ScanningScreen
    import inspect
    source = inspect.getsource(ScanningScreen)
    assert "ProgressBar" in source, "ScanningScreen missing ProgressBar"
    assert "RichLog" in source, "ScanningScreen missing RichLog (scrollable log)"


# ============================================================================
# Regression: v5.10 features still work
# ============================================================================

def test_v510_no_skfuzzy_in_deps():
    """v5.11: scikit-fuzzy must NOT be in dependencies (removed in v5.10)."""
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    content = pyproject.read_text()
    # Extract just the dependency lines (lines with quotes), skip comments
    deps_section = content.split("dependencies = [")[1].split("]")[0]
    dep_lines = [line.strip() for line in deps_section.split("\n")
                 if line.strip().startswith('"')]
    for dep in dep_lines:
        assert "scikit-fuzzy" not in dep, f"scikit-fuzzy still in deps: {dep}"


def test_v510_dashboard_uses_platform_opener():
    """v5.11: v5.10 macOS dashboard fix must still be present."""
    cli_path = Path(__file__).resolve().parent.parent / "loomscan" / "cli" / "__init__.py"
    content = cli_path.read_text()
    assert "subprocess.Popen(['open'" in content or "['open'" in content, (
        "macOS 'open' command not found in dashboard code"
    )


def test_v510_adaptive_worker_count():
    """v5.11: v5.10 adaptive max_workers must still be present."""
    orch_path = Path(__file__).resolve().parent.parent / "loomscan" / "orchestrator.py"
    content = orch_path.read_text()
    assert "cpu_count" in content, "Adaptive worker count missing"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
