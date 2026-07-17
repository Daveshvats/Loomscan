"""v7.5.6: Aggregator for v4 analyzers — moved from v4_restored.py.

This module contains ONLY the analyze_all() aggregator function. The actual
analysis implementations live in their respective modules:
  - expanded_rules, codebase_understanding, semantic_bl, multi_lang_null,
    multi_lang_typestate, multi_lang_taint, multi_lang_contracts

v4_restored.py is deprecated and will be removed in v8.0. This file is the
replacement for the aggregator function.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import List

from .v4_types import UnifiedFinding

_logger = logging.getLogger("loomscan.v4_aggregator")

try:
    from .normalized_ast import parse_file, get_language, _HAS_TS
except ImportError:
    _HAS_TS = False

try:
    from ._paths import is_skipped_dir
except ImportError:
    _skip = {".git", "__pycache__", ".venv", "venv", "node_modules", ".loomscan-cache",
             "build", "dist", "target", ".pytest_cache", ".loomscan-reports", ".loomscan-fixes"}
    def is_skipped_dir(path: Path) -> bool:
        return any(part in _skip for part in path.parts)


def _detect_lang_by_ext(file_path: Path) -> str:
    ext = file_path.suffix.lower()
    if ext == ".py": return "python"
    if ext in (".js", ".jsx", ".mjs", ".cjs"): return "javascript"
    if ext in (".ts", ".tsx"): return "typescript"
    if ext == ".go": return "go"
    if ext == ".java": return "java"
    if ext in (".c", ".h"): return "c"
    if ext in (".cpp", ".cc", ".cxx", ".hpp", ".hxx"): return "cpp"
    if ext == ".rs": return "rust"
    if ext in (".php", ".phtml"): return "php"
    if ext in (".rb", ".rake"): return "ruby"
    if ext == ".cs": return "csharp"
    if ext in (".kt", ".kts"): return "kotlin"
    if ext == ".swift": return "swift"
    if ext in (".scala", ".sc"): return "scala"
    return "unknown"


def analyze_all(repo_root: Path) -> List[UnifiedFinding]:
    """Run all v4 analyzers on a repo. v7.5.6: Moved from v4_restored.py."""
    # Import here to avoid circular deps
    from .expanded_rules import (
        scan_expanded_js, scan_expanded_java, scan_expanded_repo,
    )
    from .codebase_understanding import analyze_codebase
    from .semantic_bl import detect_semantic_bl, detect_semantic_repo
    from .multi_lang_null import detect_null_dereference_multi, detect_null_repo
    from .multi_lang_typestate import (
        detect_state_machine_multi, detect_typestate_multi,
        detect_spec_mining_multi,
    )
    from .multi_lang_taint import detect_cpg_taint_multi
    from .multi_lang_contracts import detect_contracts_multi, auto_fix_multi
    from .normalized_ast import get_language as _get_language

    # Import complexity/quality from v4_restored (they're defined there)
    # These could be extracted too, but they're simple and only used here.
    try:
        from .v4_restored import detect_complexity_multi, detect_code_quality_multi
    except Exception:
        detect_complexity_multi = lambda f: []
        detect_code_quality_multi = lambda f: []

    findings: List[UnifiedFinding] = []
    count = 0
    for f in sorted(Path(repo_root).rglob("*")):
        if not f.is_file() or is_skipped_dir(f) or count >= 300:
            continue
        lang = _get_language(f) if _HAS_TS else _detect_lang_by_ext(f)
        if lang == "unknown" and f.suffix != ".py":
            continue
        count += 1
        try:
            if f.suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
                findings.extend(scan_expanded_js(f))
            if f.suffix == ".java":
                findings.extend(scan_expanded_java(f))
            if lang != "unknown":
                findings.extend(detect_semantic_bl(f))
                findings.extend(detect_null_dereference_multi(f))
            findings.extend(detect_complexity_multi(f))
            findings.extend(detect_code_quality_multi(f))
            if lang != "unknown":
                findings.extend(detect_contracts_multi(f))
                findings.extend(detect_cpg_taint_multi(f))
            if lang != "unknown" and _HAS_TS:
                tree = parse_file(f)
                if tree:
                    findings.extend(detect_state_machine_multi(tree))
                    findings.extend(detect_typestate_multi(tree))
        except Exception as e:
            _logger.warning("v4 aggregator: %s failed: %s", f.name, e)

    # Repo-level scans
    try:
        findings.extend(scan_expanded_repo(repo_root))
        _, cu_findings = analyze_codebase(repo_root)
        findings.extend(cu_findings)
        findings.extend(detect_semantic_repo(repo_root))
        findings.extend(detect_null_repo(repo_root))
        findings.extend(detect_spec_mining_multi(repo_root))
        for f in sorted(Path(repo_root).rglob("*")):
            if not f.is_file() or is_skipped_dir(f):
                continue
            try:
                findings.extend(auto_fix_multi(f))
            except Exception:
                pass
    except Exception as e:
        _logger.warning("v4 aggregator: repo-level scan failed: %s", e)

    return findings
