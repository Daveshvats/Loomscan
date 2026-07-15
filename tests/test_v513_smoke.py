"""v5.13 smoke tests — TUI redesign: responsive layout, cosmetics, worker bug fix.

Covers:
  1. _run_scan worker bug fixed (no 'worker' parameter)
  2. Responsive CSS (uses 1fr, min-width, max-width — not fixed sizes)
  3. Bordered panels with titles
  4. Header + Footer in app
  5. RadioSet for engine selection (instead of individual RadioButtons)
  6. Stats sidebar in results screen
  7. All screens use responsive layout
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def test_version_513():
    """v5.13+: version must be >= 5.13.0."""
    import loomscan
    v = tuple(int(x) for x in loomscan.__version__.split("."))
    assert v[0] >= 7 or v >= (5, 13, 0), f"Version {loomscan.__version__} < 5.13.0"


def test_pyproject_513():
    """v5.13+: pyproject.toml must match __version__."""
    import loomscan
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    assert f'version = "{loomscan.__version__}"' in pyproject.read_text()


# ============================================================================

def test_run_scan_no_worker_param():
    """v5.13: _run_scan must NOT take a 'worker' parameter (was a crash bug)."""
    pytest.importorskip("textual")
    import inspect
    from loomscan.tui.screens.scanning import ScanningScreen
    sig = inspect.signature(ScanningScreen._run_scan)
    assert "worker" not in sig.parameters, (
        f"_run_scan still has 'worker' param: {sig.parameters}"
    )


def test_app_has_header_footer():
    """v5.13+: App must have header + footer."""
    pytest.importorskip("textual")
    import inspect
    from loomscan.tui.app import LoomScanApp
    source = inspect.getsource(LoomScanApp.compose)
    assert "Footer" in source or "footer" in source, "App missing Footer"
    # v5.15 uses #logo-text instead of Header/#app-header
    assert "logo" in source or "app-header" in source or "Header" in source,         "App missing header/logo"


def test_welcome_uses_responsive_css():
    """v5.13: WelcomeScreen must use responsive CSS (1fr, min-width, max-width)."""
    pytest.importorskip("textual")
    screen_path = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "screens" / "welcome.py"
    content = screen_path.read_text()
    assert "1fr" in content or "max-width" in content, (
        "WelcomeScreen doesn't use responsive CSS"
    )
    assert "border:" in content, "WelcomeScreen missing bordered panels"
    assert "$accent" in content, "WelcomeScreen missing accent color"


def test_config_uses_radioset():
    """v5.13: ConfigScreen must use RadioSet (not individual RadioButtons)."""
    pytest.importorskip("textual")
    screen_path = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "screens" / "config.py"
    content = screen_path.read_text()
    assert "RadioSet" in content, "ConfigScreen missing RadioSet"
    assert "engine-radioset" in content, "ConfigScreen missing engine-radioset id"


def test_config_responsive_css():
    """v5.13: ConfigScreen must use responsive CSS."""
    pytest.importorskip("textual")
    screen_path = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "screens" / "config.py"
    content = screen_path.read_text()
    assert "1fr" in content or "max-width" in content
    assert "border:" in content


def test_scanning_3_panel_layout():
    """v5.13: ScanningScreen must have 3 panels (mascot/progress/log)."""
    pytest.importorskip("textual")
    screen_path = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "screens" / "scanning.py"
    content = screen_path.read_text()
    assert "mascot-panel" in content
    assert "progress-panel" in content
    assert "log-panel" in content


def test_scanning_responsive_css():
    """v5.13: ScanningScreen must use responsive CSS."""
    pytest.importorskip("textual")
    screen_path = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "screens" / "scanning.py"
    content = screen_path.read_text()
    assert "1fr" in content or "max-width" in content


def test_results_has_stats_sidebar():
    """v5.13: ResultsScreen must have a stats sidebar."""
    pytest.importorskip("textual")
    screen_path = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "screens" / "results.py"
    content = screen_path.read_text()
    assert "stats-panel" in content, "ResultsScreen missing stats sidebar"
    assert "stat-critical" in content
    assert "stat-high" in content
    assert "stat-medium" in content
    assert "stat-low" in content


def test_results_responsive_css():
    """v5.13: ResultsScreen must use responsive CSS."""
    pytest.importorskip("textual")
    screen_path = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "screens" / "results.py"
    content = screen_path.read_text()
    assert "1fr" in content or "max-width" in content


def test_no_text_size_anywhere():
    """v5.13: No 'text-size' CSS property in ANY TUI file."""
    tui_dir = Path(__file__).resolve().parent.parent / "loomscan" / "tui"
    for py_file in tui_dir.rglob("*.py"):
        content = py_file.read_text()
        assert "text-size:" not in content, (
            f"{py_file.name} still has 'text-size:' CSS property (invalid)"
        )


def test_app_has_global_css():
    """v5.13: App must have global CSS with theme/styling."""
    pytest.importorskip("textual")
    import inspect
    from loomscan.tui.app import LoomScanApp
    assert hasattr(LoomScanApp, 'CSS'), "App missing CSS attribute"
    assert "$accent" in LoomScanApp.CSS, "App CSS missing accent color"
    assert "Header" in LoomScanApp.CSS or "Footer" in LoomScanApp.CSS, (
        "App CSS missing Header/Footer styling"
    )


# ============================================================================
# Regression: v5.12 features still work
# ============================================================================

def test_v512_cwe_map_still_exists():
    """v5.13: v5.12 CWE mapping must still exist."""
    from loomscan.orchestrator import _SINK_TYPE_CWE_MAP
    assert len(_SINK_TYPE_CWE_MAP) >= 10


def test_v512_engine_selection_still_works():
    """v5.13: v5.12 engine selection must still work."""
    screen_path = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "screens" / "config.py"
    content = screen_path.read_text()
    assert "engine-auto" in content
    assert "engine-rust" in content
    assert "engine-semgrep" in content
    assert "engine-python" in content


def test_v512_full_extra_includes_all():
    """v5.13: v5.12 [full] extra must still include Rust + TUI."""
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    content = pyproject.read_text()
    full_start = content.find("full = [")
    full_section = content[full_start:full_start + 800]
    assert "loomscan-regex" in full_section
    assert "textual" in full_section


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
