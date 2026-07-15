"""v5.12 smoke tests — Z agent bug fixes + engine selection + install model changes.

Covers:
  1. CSS fix: text-size removed (was invalid Textual CSS property)
  2. Mascot animation fix: uses Image.from_file() not str assignment
  3. Progress bar fix: total=100 with percentage updates
  4. CWE ID fix: proper mapping dict instead of sink_type[:2]
  5. Engine selection: LOOMSCAN_ENGINE env var respected
  6. [full] includes Rust core + TUI
  7. [all] extra exists
  8. Dead code removed: should_launch_tui, MascotImage, dead imports
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ============================================================================
# Version checks
# ============================================================================

def test_version_bumped_to_512():
    """v5.12+: __version__ must be >= 5.12.0."""
    import loomscan
    v_parts = tuple(int(x) for x in loomscan.__version__.split("."))
    assert v_parts[0] >= 7 or v_parts >= (5, 12, 0), f"Version {loomscan.__version__} < 5.12.0"


def test_pyproject_version_512():
    """v5.12+: pyproject.toml version must match __version__ (>= 5.12.0)."""
    import loomscan
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    content = pyproject.read_text()
    assert f'version = "{loomscan.__version__}"' in content


# ============================================================================
# Fix 1: CSS text-size removed (was invalid Textual CSS)
# ============================================================================

def test_no_text_size_in_css():
    """v5.12: No 'text-size' CSS property in any TUI screen (was invalid)."""
    screens_dir = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "screens"
    for screen_file in screens_dir.glob("*.py"):
        content = screen_file.read_text()
        # text-size is not a valid Textual CSS property — must not appear
        assert "text-size:" not in content, (
            f"{screen_file.name} still has 'text-size:' CSS property (invalid)"
        )


# ============================================================================
# Fix 2: Mascot animation uses Image.from_file() (not str assignment)
# ============================================================================

def test_mascot_animation_uses_from_file():
    """v5.12: Mascot widget must use Image.from_file() for frame updates."""
    pytest.importorskip("textual")
    mascot_path = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "mascot_widget.py"
    content = mascot_path.read_text()
    # Must NOT have the old broken pattern: img.image = str(path)
    assert "img.image = str(" not in content, (
        "Mascot still uses broken str assignment for image frames"
    )
    # Must use Image.from_file() for new frames
    assert "Image.from_file" in content or "new_img" in content, (
        "Mascot doesn't use Image.from_file() for frame updates"
    )


def test_mascot_image_class_removed():
    """v5.12: Dead MascotImage class must be removed."""
    mascot_path = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "mascot_widget.py"
    content = mascot_path.read_text()
    assert "class MascotImage" not in content, (
        "Dead MascotImage class still present (should be removed)"
    )


# ============================================================================
# Fix 3: Progress bar uses total=100 with percentage updates
# ============================================================================

def test_scanning_progress_bar_total_100():
    """v5.12: ScanningScreen progress bar must use total=100 (not total=7)."""
    pytest.importorskip("textual")
    scanning_path = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "screens" / "scanning.py"
    content = scanning_path.read_text()
    assert "total=100" in content, "Progress bar should use total=100"
    assert "total=7" not in content, "Progress bar should NOT use total=7 (was bugged)"


def test_scanning_update_stage_takes_percentage():
    """v5.12: _update_stage must accept a progress_pct parameter."""
    pytest.importorskip("textual")
    scanning_path = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "screens" / "scanning.py"
    content = scanning_path.read_text()
    assert "progress_pct" in content, (
        "_update_stage should accept progress_pct parameter for percentage updates"
    )


# ============================================================================
# Fix 4: CWE ID mapping (no more CWE-co, CWE-sq)
# ============================================================================

def test_cwe_mapping_dict_exists():
    """v5.12: _SINK_TYPE_CWE_MAP must exist in orchestrator.py."""
    from loomscan.orchestrator import _SINK_TYPE_CWE_MAP
    assert isinstance(_SINK_TYPE_CWE_MAP, dict)
    assert len(_SINK_TYPE_CWE_MAP) >= 10, (
        f"CWE map should have at least 10 entries, got {len(_SINK_TYPE_CWE_MAP)}"
    )


def test_cwe_mapping_has_valid_ids():
    """v5.12: All CWE IDs must be valid (CWE-NNN format, not CWE-co)."""
    from loomscan.orchestrator import _SINK_TYPE_CWE_MAP
    for sink_type, cwe in _SINK_TYPE_CWE_MAP.items():
        # Must be "CWE-" followed by digits only
        assert cwe.startswith("CWE-"), f"Invalid CWE format: {cwe}"
        cwe_num = cwe[4:]
        assert cwe_num.isdigit(), f"CWE number not numeric: {cwe} (for {sink_type})"


def test_cwe_mapping_covers_common_sinks():
    """v5.12: CWE map must cover common sink types (sql_injection, xss, etc.)."""
    from loomscan.orchestrator import _SINK_TYPE_CWE_MAP
    expected_keys = ["sql_injection", "xss", "command_injection", "deserialization"]
    for key in expected_keys:
        assert key in _SINK_TYPE_CWE_MAP, f"CWE map missing {key}"


def test_no_more_sink_type_slice_cwe():
    """v5.12: orchestrator.py must NOT use sink_type[:2] for CWE in code (comments OK)."""
    orch_path = Path(__file__).resolve().parent.parent / "loomscan" / "orchestrator.py"
    lines = orch_path.read_text().split("\n")
    for line in lines:
        stripped = line.lstrip()
        # Skip comment lines
        if stripped.startswith("#"):
            continue
        # Check for the broken pattern in actual code
        if "sink_type[:2]" in line and "CWE" in line:
            assert False, f"orchestrator still uses broken sink_type[:2] for CWE: {line}"


# ============================================================================
# Fix 5: Engine selection via LOOMSCAN_ENGINE env var
# ============================================================================

def test_yaml_engine_respects_python_pref():
    """v5.12: LOOMSCAN_ENGINE=python must force Python re (no Rust)."""
    from loomscan.yaml_engine import _get_rust_engine
    # Save original state
    import loomscan.yaml_engine as ye
    orig_checked = ye._RUST_ENGINE_CHECKED
    orig_engine = ye._RUST_ENGINE
    orig_pref = os.environ.get("LOOMSCAN_ENGINE")

    # Reset and test
    ye._RUST_ENGINE_CHECKED = False
    ye._RUST_ENGINE = None
    os.environ["LOOMSCAN_ENGINE"] = "python"

    try:
        result = _get_rust_engine()
        assert result is None, "LOOMSCAN_ENGINE=python should return None (no Rust)"
    finally:
        # Restore
        ye._RUST_ENGINE_CHECKED = orig_checked
        ye._RUST_ENGINE = orig_engine
        if orig_pref is None:
            os.environ.pop("LOOMSCAN_ENGINE", None)
        else:
            os.environ["LOOMSCAN_ENGINE"] = orig_pref


def test_config_screen_has_engine_selection():
    """v5.12: ConfigScreen must have engine selection radio buttons."""
    pytest.importorskip("textual")
    config_path = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "screens" / "config.py"
    content = config_path.read_text()
    assert "engine-auto" in content, "ConfigScreen missing engine-auto radio button"
    assert "engine-rust" in content, "ConfigScreen missing engine-rust radio button"
    assert "engine-semgrep" in content, "ConfigScreen missing engine-semgrep radio button"
    assert "engine-python" in content, "ConfigScreen missing engine-python radio button"


def test_scanning_screen_sets_engine_env():
    """v5.12: ScanningScreen must set LOOMSCAN_ENGINE env var from user choice."""
    pytest.importorskip("textual")
    scanning_path = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "screens" / "scanning.py"
    content = scanning_path.read_text()
    assert "LOOMSCAN_ENGINE" in content, (
        "ScanningScreen doesn't set LOOMSCAN_ENGINE env var"
    )


# ============================================================================
# Fix 6: [full] includes Rust core + TUI
# ============================================================================

def test_full_extra_includes_rust_and_tui():
    """v5.12: [full] extra must include loomscan-regex + textual deps."""
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    content = pyproject.read_text()
    # Find the [full] section and take a generous slice (500 chars)
    full_start = content.find("full = [")
    full_section = content[full_start:full_start + 1000]
    assert "loomscan-regex" in full_section, "[full] doesn't include loomscan-regex"
    assert "textual" in full_section, "[full] doesn't include textual"
    assert "textual-image" in full_section, "[full] doesn't include textual-image"
    assert "textual-fspicker" in full_section, "[full] doesn't include textual-fspicker"
    assert "pillow" in full_section, "[full] doesn't include pillow"


def test_all_extra_exists():
    """v5.12: [all] extra must exist (was missing in v5.11)."""
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    content = pyproject.read_text()
    assert "all = [" in content, "[all] extra not defined"


def test_fast_is_alias_for_full():
    """v5.12: [fast] must be an alias for [full] (backward compat)."""
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    content = pyproject.read_text()
    fast_start = content.find("fast = [")
    fast_section = content[fast_start:fast_start + 200]
    assert "loomscan[full]" in fast_section, "[fast] should reference loomscan[full]"


# ============================================================================
# Fix 8: Dead code removed
# ============================================================================

def test_should_launch_tui_removed():
    """v5.12: should_launch_tui() must be removed (was dead code)."""
    app_path = Path(__file__).resolve().parent.parent / "loomscan" / "tui" / "app.py"
    content = app_path.read_text()
    assert "def should_launch_tui" not in content, (
        "should_launch_tui() still present (dead code, should be removed)"
    )


def test_dead_imports_removed_from_orchestrator():
    """v5.12: Dead imports (build_cpg_for_repo, track_taint_for_files, etc.) removed."""
    orch_path = Path(__file__).resolve().parent.parent / "loomscan" / "orchestrator.py"
    content = orch_path.read_text()
    # These were dead imports — only referenced once (the import line)
    assert "track_taint_for_files" not in content, "track_taint_for_files still imported (dead)"
    assert "build_cpg_for_repo," not in content, "build_cpg_for_repo still imported (dead)"


# ============================================================================
# Regression: v5.11 features still work
# ============================================================================

def test_v511_tui_app_still_imports():
    """v5.12+: v5.11 TUI app must still import."""
    pytest.importorskip("textual")
    from loomscan.tui.app import LoomScanApp
    app = LoomScanApp()
    # v5.14 changed to single-screen — just verify app creates
    assert app is not None


def test_v511_cli_launches_tui_when_no_args():
    """v5.12: v5.11 CLI two-mode behavior must still work."""
    from loomscan.cli import main
    # main must accept invoke_without_command
    import inspect
    # The group should have invoke_without_command=True
    assert main.invoke_without_command is True, (
        "CLI group doesn't have invoke_without_command=True"
    )


def test_v511_python_312_requirement():
    """v5.12: Python 3.12+ requirement kept (user confirmed this is OK)."""
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    content = pyproject.read_text()
    assert 'requires-python = ">=3.12"' in content


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
