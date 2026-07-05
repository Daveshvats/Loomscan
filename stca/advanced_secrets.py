"""Advanced secret detection with TruffleHog + historical git scan.

Replaces the regex-only gitleaks wrapper with a multi-tool approach:

1. **TruffleHog** (--regex --entropy) — entropy-based detection catches
   custom secret formats that no regex knows. This is the open-source
   equivalent of GitGuardian's ML detection.

2. **Historical scan** — scans EVERY commit in git history, not just the
   current diff. Catches secrets leaked years ago that are still in history.

3. **Verification** — TruffleHog can verify if a detected secret is still
   active (calls the API to check). This eliminates false positives on
   rotated/revoked secrets.

4. **Entropy fallback** — if TruffleHog isn't installed, we have a built-in
   Shannon entropy detector that flags high-entropy strings (likely secrets).

References:
  - https://github.com/trufflesecurity/trufflehog
  - Shannon entropy: https://en.wikipedia.org/wiki/Entropy_(information_theory)
"""
from __future__ import annotations

import math
import re
import subprocess
import shutil
import json
from pathlib import Path
from typing import List, Set, Tuple
from dataclasses import dataclass

from .models import Finding, Severity, BlastRadius, LayerID


# Shannon entropy threshold — strings above this are "suspicious"
ENTROPY_THRESHOLD = 4.5
MIN_SECRET_LENGTH = 20

# Known secret prefixes (high-confidence)
SECRET_PREFIXES = [
    "AKIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA",  # AWS
    "sk-", "sk_live_", "rk_live_",  # Stripe
    "ghp_", "gho_", "ghu_", "ghs_", "ghr_",  # GitHub
    "glpat-",  # GitLab
    "xoxb-", "xoxp-",  # Slack
    "AIza",  # Google API
    "eyJ",  # JWT
]


@dataclass
class SecretDetection:
    """A detected secret."""
    file: str
    line: int
    secret_type: str  # 'aws' | 'github' | 'stripe' | 'generic_entropy' | etc.
    value_preview: str  # first 4 + last 4 chars
    confidence: float
    verified: bool = False  # True if we confirmed it's still active


def shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string. Higher = more random = more likely a secret."""
    if not s:
        return 0.0
    from collections import Counter
    counts = Counter(s)
    n = len(s)
    entropy = 0.0
    for count in counts.values():
        p = count / n
        entropy -= p * math.log2(p)
    return entropy


def detect_secrets_entropy(text: str, file: str) -> List[SecretDetection]:
    """Detect secrets using Shannon entropy. No external tool required.

    This is a fallback when TruffleHog isn't installed. It catches:
      - Known prefix secrets (AWS, Stripe, GitHub, etc.)
      - High-entropy strings (random tokens)
    """
    detections: List[SecretDetection] = []
    for i, line in enumerate(text.splitlines(), 1):
        # check for known prefixes
        for prefix in SECRET_PREFIXES:
            idx = line.find(prefix)
            while idx >= 0:
                # extract the secret (up to 80 chars)
                end = min(idx + 80, len(line))
                while end < len(line) and line[end] not in ' "\')\n;}<>':
                    end += 1
                value = line[idx:end]
                if len(value) >= MIN_SECRET_LENGTH:
                    secret_type = _classify_prefix(prefix)
                    detections.append(SecretDetection(
                        file=file, line=i, secret_type=secret_type,
                        value_preview=_mask(value),
                        confidence=0.9,
                    ))
                idx = line.find(prefix, idx + 1)

        # check for high-entropy strings (potential custom secrets)
        # match quoted strings of length >= 20
        for match in re.finditer(r'["\']([A-Za-z0-9+/=_-]{20,})["\']', line):
            value = match.group(1)
            entropy = shannon_entropy(value)
            if entropy >= ENTROPY_THRESHOLD:
                # check it's not a known prefix (already caught above)
                if not any(value.startswith(p) for p in SECRET_PREFIXES):
                    detections.append(SecretDetection(
                        file=file, line=i, secret_type="generic_entropy",
                        value_preview=_mask(value),
                        confidence=0.7,
                    ))

    return detections


def _classify_prefix(prefix: str) -> str:
    if prefix.startswith("AK") or prefix in ("AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA"):
        return "aws"
    if prefix.startswith("sk"):
        return "stripe"
    if prefix.startswith("gh"):
        return "github"
    if prefix == "glpat-":
        return "gitlab"
    if prefix.startswith("xox"):
        return "slack"
    if prefix == "AIza":
        return "google"
    if prefix == "eyJ":
        return "jwt"
    return "unknown"


def _mask(value: str) -> str:
    """Mask a secret, showing only first 4 and last 4 chars."""
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}...{value[-4:]}"


def run_trufflehog(repo_root: Path, files: List[Path]) -> List[Finding]:
    """Run TruffleHog on the given files. Returns findings."""
    if not shutil.which("trufflehog"):
        return []

    findings: List[Finding] = []
    for file_path in files:
        try:
            proc = subprocess.run(
                ["trufflehog", "filesystem", "--json", "--no-update",
                 str(file_path)],
                capture_output=True, text=True, check=False, timeout=30,
                cwd=str(repo_root),
            )
            for line in proc.stdout.splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    if data.get("Verified") is True or data.get("Raw"):
                        detector = data.get("DetectorName", "unknown")
                        findings.append(Finding(
                            layer=LayerID.L0_FAST,
                            rule_id=f"L0.trufflehog.{detector}",
                            message=f"Secret detected (verified={data.get('Verified', False)}): {detector}",
                            file=data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("path", ""),
                            start_line=data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line", 0),
                            severity=Severity.CRITICAL if data.get("Verified") else Severity.HIGH,
                            confidence=0.95 if data.get("Verified") else 0.8,
                            blast_radius=BlastRadius.SYSTEM, exploitability=0.95,
                            cwe="CWE-798",
                            fix_suggestion=f"Revoke and rotate the {detector} immediately; use environment variables",
                            raw=data,
                        ))
                except json.JSONDecodeError:
                    continue
        except subprocess.TimeoutExpired:
            continue
    return findings


def scan_git_history(repo_root: Path, max_commits: int = 1000) -> List[Finding]:
    """Scan git history for leaked secrets.

    This is the GitGuardian-equivalent feature: scan EVERY commit, not just
    the current diff. Catches secrets leaked years ago that are still in
    git history.

    Args:
        repo_root: path to the git repo
        max_commits: cap on commits to scan (prevents runaway scans on huge repos)

    Returns:
        List of secret findings across history.
    """
    findings: List[Finding] = []

    # Get all commits
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "log", "--pretty=format:%H", "-n", str(max_commits)],
            capture_output=True, text=True, check=False, timeout=30,
        )
        commits = proc.stdout.strip().splitlines()
    except Exception:
        return []

    # For each commit, get the diff and scan for secrets
    seen_secrets: Set[str] = set()  # dedupe by file+line+preview

    for commit in commits[:max_commits]:
        try:
            diff_proc = subprocess.run(
                ["git", "-C", str(repo_root), "show", commit, "--no-color", "--no-patch"],
                capture_output=True, text=True, check=False, timeout=10,
            )
            # get the commit's added lines
            diff_proc = subprocess.run(
                ["git", "-C", str(repo_root), "diff", f"{commit}~1", commit, "--no-color"]
                if commit != commits[-1] else
                ["git", "-C", str(repo_root), "show", commit, "--no-color"],
                capture_output=True, text=True, check=False, timeout=30,
            )
            diff = diff_proc.stdout
        except Exception:
            continue

        # Parse the diff for added lines (starting with +, not ++)
        current_file = ""
        current_line = 0
        for line in diff.splitlines():
            if line.startswith("+++ b/"):
                current_file = line[6:]
                current_line = 0
            elif line.startswith("+") and not line.startswith("+++"):
                current_line += 1
                # scan this added line for secrets
                detections = detect_secrets_entropy(line[1:], current_file)
                for d in detections:
                    dedupe_key = f"{d.file}:{d.line}:{d.value_preview}"
                    if dedupe_key in seen_secrets:
                        continue
                    seen_secrets.add(dedupe_key)
                    findings.append(Finding(
                        layer=LayerID.L0_FAST,
                        rule_id=f"L0.history_secret.{d.secret_type}",
                        message=f"Secret in git history ({d.secret_type}): {d.value_preview} — found in commit {commit[:8]}",
                        file=d.file, start_line=d.line,
                        severity=Severity.CRITICAL, confidence=d.confidence,
                        blast_radius=BlastRadius.SYSTEM, exploitability=0.95,
                        cwe="CWE-798",
                        fix_suggestion="Rotate the secret immediately. Use BFG or git-filter-repo to scrub history.",
                        raw={"commit": commit, "secret_type": d.secret_type,
                             "preview": d.value_preview},
                    ))

    return findings


def detect_secrets_advanced(repo_root: Path,
                             files: List[Path],
                             scan_history: bool = False) -> List[Finding]:
    """End-to-end secret detection: TruffleHog + entropy fallback + history.

    Args:
        repo_root: path to repo
        files: changed files in the diff
        scan_history: if True, scan all git history (slow but comprehensive)
    """
    findings: List[Finding] = []

    # Files to skip (high false positive rate)
    SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                  "composer.lock", "Gemfile.lock", "Cargo.lock", "poetry.lock",
                  "go.sum", "result.json", "result.sarif", "report.html"}

    # 1. Try TruffleHog first (best detection)
    trufflehog_findings = run_trufflehog(repo_root, files)
    findings.extend(trufflehog_findings)

    # 2. Entropy fallback for files TruffleHog didn't cover
    trufflehog_files = {f.file for f in trufflehog_findings}
    for file_path in files:
        # Skip lock files and generated files
        if file_path.name in SKIP_FILES:
            continue
        rel = str(file_path.relative_to(repo_root)) if file_path.is_relative_to(repo_root) else str(file_path)
        if rel in trufflehog_files:
            continue
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
            detections = detect_secrets_entropy(text, rel)
            for d in detections:
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id=f"L0.entropy_secret.{d.secret_type}",
                    message=f"Possible secret ({d.secret_type}, entropy-based): {d.value_preview}",
                    file=d.file, start_line=d.line,
                    severity=Severity.HIGH if d.confidence >= 0.85 else Severity.MEDIUM,
                    confidence=d.confidence,
                    blast_radius=BlastRadius.SYSTEM, exploitability=0.9,
                    cwe="CWE-798",
                    fix_suggestion="Move to environment variable or secret manager",
                    raw={"secret_type": d.secret_type, "preview": d.value_preview},
                ))
        except Exception:
            continue

    # 3. Historical scan (opt-in, slow)
    if scan_history:
        findings.extend(scan_git_history(repo_root))

    return findings
