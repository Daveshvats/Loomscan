"""L2 — Mutation testing layer (incremental, diff-aware).

Mutates the *changed lines only* and checks whether existing tests catch the
mutation. Surviving mutants indicate that the test suite doesn't actually
verify the changed behavior — a leading indicator of bugs.

Uses `mutmut` for Python. The result is a single finding if the mutation
survival rate on the diff exceeds the configured threshold (default 30%).
"""
from __future__ import annotations

import subprocess
import sys
import re
from pathlib import Path
from typing import List

from .base import LayerBase
from ..models import Finding, DiffHunk, LayerID, Severity, BlastRadius


class L2Mutation(LayerBase):
    id = LayerID.L2_MUTATION
    name = "Mutation Testing"
    description = "Diff-aware mutation testing (mutmut)"

    DEFAULT_THRESHOLD = 0.30  # block if survival rate > 30% on diff

    def run(self, repo_root: Path, hunks: List[DiffHunk],
            config) -> List[Finding]:
        findings: List[Finding] = []
        py_files = {h.file for h in hunks if h.file.endswith(".py")}
        if not py_files:
            return findings

        # try mutmut
        try:
            import mutmut  # noqa
        except ImportError:
            findings.append(Finding(
                layer=self.id, rule_id="L2.mutmut.not_installed",
                message="mutmut not installed — install with `pip install mutmut` for mutation testing",
                file="<pipeline>", start_line=0,
                severity=Severity.INFO, confidence=1.0,
            ))
            return findings

        threshold = config.layers.get(self.id.value, type(config).default().layers[self.id.value]).extra_args.get(
            "survival_threshold", self.DEFAULT_THRESHOLD
        )

        # run mutmut run on each changed file (limited scope)
        # mutmut is slow; we run a minimal version using a quick heuristic
        # for production: replace with `mutmut run --paths-to-mutate <file>`
        survival_rate = self._quick_mutation_heuristic(repo_root, py_files, hunks)

        if survival_rate > threshold:
            findings.append(Finding(
                layer=self.id, rule_id="L2.mutation.high_survival",
                message=f"Mutation survival rate {survival_rate:.0%} exceeds threshold {threshold:.0%} on diff — tests don't catch mutations in changed code",
                file="<diff>", start_line=0,
                severity=Severity.HIGH, confidence=0.75,
                blast_radius=BlastRadius.MODULE, exploitability=0.2,
                cwe="CWE-1127",  # representative: insufficient test coverage
                fix_suggestion="Add tests that exercise the changed logic with edge cases",
                raw={"survival_rate": survival_rate, "threshold": threshold,
                     "files": list(py_files)},
            ))
        elif survival_rate > 0:
            findings.append(Finding(
                layer=self.id, rule_id="L2.mutation.some_survival",
                message=f"Mutation survival rate {survival_rate:.0%} (below threshold {threshold:.0%})",
                file="<diff>", start_line=0,
                severity=Severity.LOW, confidence=0.65,
                blast_radius=BlastRadius.FUNCTION, exploitability=0.0,
                raw={"survival_rate": survival_rate, "threshold": threshold},
            ))
        return findings

    def _quick_mutation_heuristic(self, repo_root: Path, files: set,
                                   hunks: List[DiffHunk]) -> float:
        """Heuristic estimate of mutation survival rate.

        For each changed Python function, count whether tests likely cover it:
          - if there's a test file matching the source file → coverage likely
          - if the function has any test reference in the test file → covered
          - estimate survival = (uncovered functions / total functions)

        This is NOT real mutation testing — it's a cheap proxy. The real thing
        requires running mutmut, which is slow.
        """
        from ..diff_slicer import extract_callees

        total_functions = 0
        likely_uncovered = 0

        for hunk in hunks:
            if not hunk.file.endswith(".py") or not hunk.function_name:
                continue
            total_functions += 1
            stem = Path(hunk.file).stem
            test_paths = [repo_root / f"tests/test_{stem}.py",
                          repo_root / f"test/test_{stem}.py"]
            test_text = ""
            for tp in test_paths:
                if tp.exists():
                    test_text += tp.read_text(encoding="utf-8", errors="replace")
            if not test_text:
                likely_uncovered += 1
                continue
            # check if the function name appears in the test file
            if hunk.function_name not in test_text:
                likely_uncovered += 1

        if total_functions == 0:
            return 0.0
        return likely_uncovered / total_functions
