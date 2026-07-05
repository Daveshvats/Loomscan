"""Inline suppression mechanism.

Allows developers to suppress findings with comments:
    # stca: ignore
    eval(user_input)  # stca: ignore[L0.sast.mini:py-eval]
    # stca: ignore L0.sast.mini:py-eval  (rule-specific)

Suppressions are tracked and reported in the output (not silently dropped)
so reviewers can see what was suppressed and audit it.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Set, Tuple, Optional
from dataclasses import dataclass


@dataclass
class Suppression:
    file: str
    line: int
    rule_id: Optional[str]  # None = all rules
    reason: Optional[str]
    raw: str


SUPPRESSION_PATTERNS = [
    # stca: ignore  (suppresses everything on this line)
    re.compile(r"stca:\s*ignore\b(?:\s*\[([^\]]+)\])?(?:\s*--\s*(.*))?$", re.IGNORECASE),
    # noqa: stca=L0.sast.mini:py-eval  (PEP-8 compatible)
    re.compile(r"noqa:\s*stca=([^\s]+)", re.IGNORECASE),
    # pylint-style: # pylint: disable=stca-L0.sast.mini:py-eval
    re.compile(r"pylint:\s*disable=stca-([^\s]+)", re.IGNORECASE),
]


def find_suppressions(file_path: Path) -> List[Suppression]:
    """Find all inline suppressions in a file."""
    if not file_path.exists():
        return []
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []

    suppressions: List[Suppression] = []
    for i, line in enumerate(lines, start=1):
        for pat in SUPPRESSION_PATTERNS:
            m = pat.search(line)
            if m:
                rule_id = m.group(1) if m.lastindex and m.lastindex >= 1 else None
                reason = m.group(2) if m.lastindex and m.lastindex >= 2 else None
                suppressions.append(Suppression(
                    file=str(file_path),
                    line=i,
                    rule_id=rule_id,
                    reason=reason,
                    raw=line.strip(),
                ))
                break
    return suppressions


def is_suppressed(finding_file: str, finding_line: int, finding_rule_id: str,
                  suppressions: List[Suppression]) -> Tuple[bool, Optional[Suppression]]:
    """Check if a finding is suppressed by an inline comment.

    A suppression on line N suppresses findings on:
      - line N (same line)
      - line N+1 (comment on the line above the finding)
    """
    for sup in suppressions:
        if sup.file != finding_file:
            # compare just filenames for robustness
            if Path(sup.file).name != Path(finding_file).name:
                continue
        if sup.line == finding_line or sup.line == finding_line - 1:
            if sup.rule_id is None:
                return True, sup
            if sup.rule_id == finding_rule_id:
                return True, sup
            # also check prefix match (e.g., "L0.sast.mini" matches "L0.sast.mini:py-eval")
            if finding_rule_id.startswith(sup.rule_id):
                return True, sup
    return False, None


def filter_suppressed(findings: list, repo_root: Path) -> Tuple[list, list]:
    """Filter findings, returning (kept, suppressed)."""
    # collect suppressions per file
    sup_by_file: dict = {}
    for f in findings:
        file_path = repo_root / f.file
        if str(file_path) not in sup_by_file and file_path.exists():
            sup_by_file[str(file_path)] = find_suppressions(file_path)

    kept = []
    suppressed = []
    for f in findings:
        file_path = repo_root / f.file
        sups = sup_by_file.get(str(file_path), [])
        is_sup, sup = is_suppressed(f.file, f.start_line, f.rule_id, sups)
        if is_sup:
            suppressed.append((f, sup))
        else:
            kept.append(f)
    return kept, suppressed
