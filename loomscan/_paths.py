"""v7.2: Unified path utilities — single source of truth for skip dirs.

Fixes the P0 feedback-loop bug: 28 different skip_dirs definitions across
the codebase, each slightly different. Most missed .loomscan-reports/,
causing LoomScan to scan its own output files on consecutive runs.
"""
from __future__ import annotations

from pathlib import Path
from typing import Set


# Single source of truth — all LoomScan artifacts and common skip dirs.
# Every module that discovers files MUST use this set.
DEFAULT_SKIP_DIRS: Set[str] = {
    # LoomScan artifacts (MUST be skipped to prevent feedback loops)
    ".loomscan-cache",
    ".loomscan-reports",
    ".loomscan-fixes",
    # LoomScan artifact files (handled separately in file-level checks)
    # See is_loomscan_artifact() below
    # Python
    "__pycache__",
    ".venv",
    "venv",
    "env",
    ".eggs",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "site-packages",
    # JavaScript
    "node_modules",
    "bower_components",
    ".npm",
    ".yarn",
    # Build artifacts
    "build",
    "dist",
    "target",
    "out",
    ".tox",
    ".coverage",
    "htmlcov",
    ".nyc_output",
    # VCS
    ".git",
    ".hg",
    ".svn",
    # IDE
    ".idea",
    ".vscode",
    ".vs",
    # Other
    ".loomscan-projects",
}


# LoomScan artifact files that should never be scanned
LOOMSCAN_ARTIFACT_FILES: Set[str] = {
    ".loomscan-hotspots.json",
    ".loomscan-audit.log",
    ".loomscan-issues.db",
    ".loomscan-baseline.json",
    ".loomscan-fp-learning.json",
    ".loomscan-stats.json",
    ".loomscan-project-tuner.json",
    ".loomscanignore",
    ".loomscan.yaml",
    "loomscan-dashboard.html",
    "loomscan-report.sarif",
    "loomscan-report.json",
    "merge-review.html",
}


def is_skipped_dir(path: Path) -> bool:
    """Check if a path component is in the skip dirs set."""
    return any(part in DEFAULT_SKIP_DIRS for part in path.parts)


def is_loomscan_artifact(path: Path) -> bool:
    """Check if a file is a LoomScan artifact (should never be scanned)."""
    if path.name in LOOMSCAN_ARTIFACT_FILES:
        return True
    # Check for .loomscan-* pattern
    if path.name.startswith(".loomscan-"):
        return True
    # Check for loomscan report files
    if path.name.startswith("loomscan-") and path.suffix in (".html", ".json", ".sarif"):
        return True
    return False


def should_scan_file(path: Path, source_extensions: Set[str] | None = None) -> bool:
    """Check if a file should be scanned.

    Args:
        path: File path to check
        source_extensions: Set of allowed extensions (e.g. {'.py', '.java'})
                          If None, accepts any file
    Returns:
        True if the file should be scanned
    """
    if not path.is_file():
        return False
    if is_skipped_dir(path):
        return False
    if is_loomscan_artifact(path):
        return False
    if source_extensions is not None:
        if path.suffix.lower() not in source_extensions:
            # Also check for Dockerfile (no extension)
            if not path.name.lower().startswith("dockerfile"):
                return False
    return True
