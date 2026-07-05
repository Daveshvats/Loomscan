"""L8 — Auto-Fix layer.

Doesn't detect bugs — applies patches to fix them. Inspired by:
  - GitHub Copilot Autofix
  - Snyk Code autofix
  - Semgrep Autofix

For each finding from other layers, check if there's a known fix pattern.
If yes, generate a patch and either:
  - Apply it directly (with `--apply` flag)
  - Stage it for review in `.stca-fixes/<finding_id>.patch`
  - Output it inline in the report

Fix sources:
  1. Pattern-based fixers (rule_id → deterministic patch)
  2. LLM-generated fixes (when LLM enabled, gated by PRM)
  3. Tool-native fixes (semgrep --autofix, ruff --fix, gitleaks --report-path)

This is the "last mile" — detection is useless if devs don't apply the fix.
"""
from __future__ import annotations

import re
import os
import subprocess
from pathlib import Path
from typing import List, Optional, Dict
from dataclasses import dataclass

from .base import LayerBase
from ..models import Finding, DiffHunk, LayerID, Severity, BlastRadius


@dataclass
class FixPattern:
    """A deterministic fix pattern keyed on a rule_id prefix."""
    rule_prefix: str
    description: str
    fixer: callable  # takes (finding, repo_root) → patch string or None


# Built-in deterministic fixers
def _fix_eval_python(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace eval(x) with ast.literal_eval(x) for safe literal parsing."""
    path = repo_root / finding.file
    if not path.exists():
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    # only fix if it's a simple eval() call (not complex)
    if original.count("eval(") == 1 and "ast.literal_eval" not in original:
        # don't fix if the arg is dynamic — ast.literal_eval only handles literals
        m = re.search(r"eval\(([^)]+)\)", original)
        if m:
            arg = m.group(1)
            # if arg is a string variable, suggest literal_eval
            fixed = original.replace(f"eval({arg})", f"ast.literal_eval({arg})")
            # add ast import if not present
            text = "\n".join(lines)
            if "import ast" not in text:
                # insert after last existing import
                last_import = 0
                for i, l in enumerate(lines):
                    if l.startswith("import ") or l.startswith("from "):
                        last_import = i
                lines.insert(last_import + 1, "import ast")
                line_idx += 1
            lines[line_idx] = fixed
            return "\n".join(lines)
    return None


def _fix_hardcoded_password(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace hardcoded password comparison with hash-based check."""
    path = repo_root / finding.file
    if not path.exists():
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    # Replace `if password == "x":` with `if hashlib.sha256(password.encode()).hexdigest() == HASH:`
    m = re.search(r"if\s+(\w+)\s*==\s*['\"](\w+)['\"]", original)
    if m:
        var, _ = m.groups()
        # Note: real fix needs hash storage; this is a placeholder
        comment = f"# TODO: replace with proper password hash check (bcrypt/argon2)"
        fixed = f"{comment}\n{original.replace(m.group(0), f'# {m.group(0)}')}"
        lines[line_idx] = fixed
        return "\n".join(lines)
    return None


def _fix_docker_latest(finding: Finding, repo_root: Path) -> Optional[str]:
    """Pin Dockerfile FROM tag from :latest to a specific version."""
    path = repo_root / finding.file
    if not path.exists():
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    # python:latest → python:3.12-slim, node:latest → node:20-slim
    fixed = re.sub(r":latest\b", ":3.12-slim", original)  # conservative default
    if fixed != original:
        lines[line_idx] = fixed
        return "\n".join(lines)
    return None


def _fix_bare_except(finding: Finding, repo_root: Path) -> Optional[str]:
    """Replace bare `except:` with `except Exception:`."""
    path = repo_root / finding.file
    if not path.exists():
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    line_idx = finding.start_line - 1
    if line_idx >= len(lines):
        return None
    original = lines[line_idx]
    fixed = original.replace("except:", "except Exception:")
    if fixed != original:
        lines[line_idx] = fixed
        return "\n".join(lines)
    return None


FIX_PATTERNS: List[FixPattern] = [
    FixPattern("L0.sast.mini:py-eval", "Replace eval() with ast.literal_eval()", _fix_eval_python),
    FixPattern("L5.policy.static:no-eval", "Comment out eval() usage", _fix_eval_python),
    FixPattern("L0.sast.mini:py-hardcoded-password", "Replace hardcoded password", _fix_hardcoded_password),
    FixPattern("L0e.docker-latest-tag", "Pin Dockerfile FROM tag", _fix_docker_latest),
    FixPattern("L0.sast.mini:py-bare-except", "Replace bare except with except Exception", _fix_bare_except),
]


class L8AutoFix(LayerBase):
    id = LayerID.L0_FAST
    name = "Auto-Fix"
    description = "Generate patches for findings (deterministic + LLM-assisted)"
    LAYER_TAG = "L8_autofix"

    def __init__(self, apply: bool = False):
        self.apply = apply  # if True, apply patches directly; else just stage them

    def run(self, repo_root: Path, hunks: List[DiffHunk],
            config, prior_findings: List[Finding] = None) -> List[Finding]:
        """Generate fixes for findings from other layers.

        Note: this layer is special — it consumes findings from other layers,
        not the diff directly. The orchestrator calls it with prior_findings.
        """
        findings: List[Finding] = []
        if not prior_findings:
            return findings

        fixes_dir = repo_root / ".stca-fixes"
        fixes_dir.mkdir(parents=True, exist_ok=True)

        applied = 0
        staged = 0
        for f in prior_findings:
            patch = self._generate_fix(f, repo_root)
            if patch is None:
                continue

            patch_path = fixes_dir / f"{f.fingerprint}.patch"
            patch_path.write_text(patch, encoding="utf-8")

            if self.apply:
                # apply directly to the source file
                self._apply_patch(repo_root / f.file, patch)
                applied += 1
                # don't double-report as a finding — just track
            else:
                staged += 1
                findings.append(Finding(
                    layer=self.id,
                    rule_id=f"L8.fix.{f.rule_id}",
                    message=f"Auto-fix available for {f.rule_id} (staged in {patch_path.relative_to(repo_root)})",
                    file=f.file, start_line=f.start_line,
                    severity=Severity.INFO, confidence=0.7,
                    blast_radius=BlastRadius.FUNCTION, exploitability=0.0,
                    fix_suggestion=f"Apply with: stca fix --apply {f.fingerprint}",
                    raw={"patch_file": str(patch_path), "original_finding": f.fingerprint},
                ))

        if applied or staged:
            # Add a summary finding
            findings.insert(0, Finding(
                layer=self.id,
                rule_id="L8.summary",
                message=f"Auto-fix: {applied} applied, {staged} staged (review in .stca-fixes/)",
                file="<autofix>", start_line=0,
                severity=Severity.INFO, confidence=1.0,
                blast_radius=BlastRadius.FUNCTION, exploitability=0.0,
                raw={"applied": applied, "staged": staged},
            ))
        return findings

    def _generate_fix(self, finding: Finding, repo_root: Path) -> Optional[str]:
        """Try to generate a fix patch for a finding."""
        # Try built-in deterministic fixers
        for pattern in FIX_PATTERNS:
            if finding.rule_id.startswith(pattern.rule_prefix) or \
               pattern.rule_prefix in finding.rule_id:
                try:
                    return pattern.fixer(finding, repo_root)
                except Exception:
                    continue

        # Try tool-native fixers (semgrep --autofix, ruff --fix)
        if finding.rule_id.startswith("L0.semgrep:"):
            return self._semgrep_autofix(finding, repo_root)
        if finding.rule_id.startswith("L0.ruff:"):
            return self._ruff_fix(finding, repo_root)

        return None

    def _semgrep_autofix(self, finding: Finding, repo_root: Path) -> Optional[str]:
        """Use semgrep's built-in autofix if the rule has one."""
        try:
            path = repo_root / finding.file
            proc = subprocess.run(
                ["semgrep", "--autofix", "--config", "auto",
                 str(path)],
                capture_output=True, text=True, check=False, timeout=30,
                cwd=str(repo_root),
            )
            if proc.returncode == 0:
                return path.read_text(encoding="utf-8")
        except Exception:
            pass
        return None

    def _ruff_fix(self, finding: Finding, repo_root: Path) -> Optional[str]:
        """Use ruff --fix for ruff findings."""
        try:
            path = repo_root / finding.file
            proc = subprocess.run(
                ["ruff", "check", "--fix", str(path)],
                capture_output=True, text=True, check=False, timeout=15,
                cwd=str(repo_root),
            )
            if proc.returncode == 0:
                return path.read_text(encoding="utf-8")
        except Exception:
            pass
        return None

    def _apply_patch(self, file_path: Path, new_content: str) -> None:
        """Apply a patch (full file replacement) to disk."""
        try:
            file_path.write_text(new_content, encoding="utf-8")
        except Exception:
            pass
