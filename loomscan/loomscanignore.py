"""v5.20: Auto-generate .loomscanignore with language-aware patterns.

When a user scans a repo for the first time (no .loomscanignore exists),
LoomScan detects the languages present and generates a .loomscanignore
with appropriate exclusion patterns for those languages.

The file is automatically loaded on every subsequent scan (v5.19).
"""
from __future__ import annotations

from pathlib import Path
from typing import List, Set


# Language-specific ignore patterns
_LANGUAGE_IGNORES = {
    "python": [
        "# Python",
        "__pycache__/",
        "*.pyc",
        "*.pyo",
        "*.egg-info/",
        ".eggs/",
        "*.egg",
        "build/",
        "dist/",
        ".tox/",
        ".mypy_cache/",
        ".ruff_cache/",
        ".pytest_cache/",
        "venv/",
        ".venv/",
        "site-packages/",
    ],
    "javascript": [
        "# JavaScript / TypeScript",
        "node_modules/",
        "bower_components/",
        "*.min.js",
        "*.min.css",
        "*.min.map",
        "*.map",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        ".npm/",
        ".yarn/",
        "coverage/",
        ".nyc_output/",
    ],
    "go": [
        "# Go",
        "vendor/",
        "go.sum",
    ],
    "rust": [
        "# Rust",
        "target/",
        "Cargo.lock",
    ],
    "java": [
        "# Java",
        "target/",
        "*.class",
        "*.jar",
        ".gradle/",
        "build/",
        ".mvn/",
    ],
    "c": [
        "# C / C++",
        "*.o",
        "*.obj",
        "*.so",
        "*.dll",
        "*.dylib",
        "*.a",
        "*.lib",
        "build/",
        "cmake-build-*/",
    ],
    "ruby": [
        "# Ruby",
        "vendor/bundle/",
        "*.gem",
        "Gemfile.lock",
        ".bundle/",
    ],
    "php": [
        "# PHP",
        "vendor/",
        "composer.lock",
    ],
}

# File extension → language mapping
_EXT_TO_LANG = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".ts": "javascript", ".tsx": "javascript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".c": "c", ".cpp": "c", ".cc": "c", ".h": "c", ".hpp": "c",
    ".rb": "ruby",
    ".php": "php",
}


def detect_languages(repo_root: Path, max_files: int = 5000) -> Set[str]:
    """Detect programming languages in a repo by scanning file extensions.

    Returns a set of language names (e.g. {"python", "javascript"}).
    """
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                 "build", "dist", ".loomscan-cache", ".loomscan-reports"}
    languages: Set[str] = set()

    count = 0
    for p in repo_root.rglob("*"):
        if count >= max_files:
            break
        if not p.is_file():
            continue
        if any(part in skip_dirs for part in p.parts):
            continue
        lang = _EXT_TO_LANG.get(p.suffix.lower())
        if lang:
            languages.add(lang)
            count += 1

    return languages


def generate_loomscanignore(repo_root: Path) -> Path:
    """v5.20: Auto-generate a .loomscanignore file based on detected languages.

    If a .loomscanignore already exists, it's not overwritten.
    Returns the path to the .loomscanignore file.
    """
    ignore_path = repo_root / ".loomscanignore"
    if ignore_path.exists():
        return ignore_path  # Don't overwrite existing

    # Detect languages
    languages = detect_languages(repo_root)

    # Build ignore content
    lines = [
        "# LoomScan ignore file (auto-generated)",
        "# This file uses the same format as .gitignore",
        "# Patterns here are excluded from LoomScan scans",
        "",
        "# === Common (always included) ===",
        ".git/",
        "*.log",
        "*.tmp",
        "*.swp",
        ".DS_Store",
        "Thumbs.db",
        "",
    ]

    # Add language-specific patterns
    for lang in sorted(languages):
        patterns = _LANGUAGE_IGNORES.get(lang, [])
        if patterns:
            lines.extend(patterns)
            lines.append("")

    # Add IDE patterns
    lines.extend([
        "# === IDE ===",
        ".idea/",
        ".vscode/",
        ".vs/",
        "",
    ])

    ignore_path.write_text("\n".join(lines), encoding="utf-8")
    return ignore_path
