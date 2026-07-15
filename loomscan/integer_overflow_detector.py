"""v7.0: Integer overflow detector — type inference heuristic.

Catches integer overflow in arithmetic on business values (qty*price, amount+fee)
without type inference — uses variable name heuristics + range check detection.

Patterns:
  1. int result = qty * price  → multiplication may overflow int range
  2. int total = a + b + c     → cumulative addition may overflow
  3. long result = (long) a * b → cast shows awareness, but verify
  4. Math.addExact/multiplyExact → safe (Java 8+)
  5. Quantity * price without range check → flag

Works on Java (.java) and Python (.py).
"""
from __future__ import annotations
import re
from pathlib import Path
from typing import List, Tuple
from .models import Finding, Severity, LayerID, BlastRadius, Category

# Java patterns
_JAVA_OVERFLOW_PATTERNS = [
    # int/long = var * var (multiplication overflow risk)
    (r'\b(?:int|long|Integer|Long)\s+\w+\s*=\s*(\w+)\s*\*\s*(\w+)\s*;',
     "java.overflow.multiply",
     Severity.MEDIUM,
     "Integer overflow: multiplication may exceed int/long range. Use Math.multiplyExact() or BigInteger.",
     "CWE-190"),
    # int = a + b + c (cumulative addition)
    (r'\b(?:int|long)\s+\w+\s*=\s*\w+\s*\+\s*\w+\s*\+\s*\w+',
     "java.overflow.add_chain",
     Severity.LOW,
     "Integer overflow: chained addition may exceed range. Use Math.addExact() for safe arithmetic.",
     "CWE-190"),
    # int result = var << shift (bit shift overflow)
    (r'\b(?:int|long)\s+\w+\s*=\s*\w+\s*<<\s*\w+',
     "java.overflow.shift",
     Severity.MEDIUM,
     "Integer overflow: left shift may exceed range. Validate shift amount < 32 (int) or < 64 (long).",
     "CWE-190"),
]

# Python patterns (Python ints don't overflow, but the value may be passed to C extensions or DB)
_PYTHON_OVERFLOW_PATTERNS = [
    # qty * price in Python — fine for Python but risky if passed to DB or C extension
    (r'\b(qty|quantity|amount|price|count|total|sum|score)\b\s*\*\s*\b(qty|quantity|amount|price|count|total|sum|score)\b',
     "py.overflow.business_arithmetic",
     Severity.INFO,
     "Arithmetic on business values (qty*price) — verify range before storing in DB (int column may overflow).",
     "CWE-190"),
]

# Safe patterns (these DON'T overflow — skip them)
_SAFE_PATTERNS = [
    r'Math\.(?:addExact|subtractExact|multiplyExact|incrementExact|decrementExact)',
    r'BigInteger',
    r'BigDecimal',
    r'long\s+\w+\s*=\s*\(long\)\s*\w+\s*\*',  # explicit cast to long = safe
]

# Domain variable names that make overflow more likely (large values expected)
_DOMAIN_VARS = {'qty', 'quantity', 'amount', 'price', 'count', 'total', 'sum',
                 'score', 'population', 'size', 'length', 'capacity', 'volume'}


def scan_java_overflow(file_path: Path, repo_root: Path) -> List[Finding]:
    """Scan Java file for integer overflow risks."""
    try:
        content = file_path.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return []

    rel_path = str(file_path.relative_to(repo_root))
    findings: List[Finding] = []
    lines = content.split('\n')

    for i, line in enumerate(lines, 1):
        # Skip if line has safe patterns
        if any(re.search(sp, line) for sp in _SAFE_PATTERNS):
            continue

        for pattern, rule_id, severity, message, cwe in _JAVA_OVERFLOW_PATTERNS:
            match = re.search(pattern, line)
            if match:
                # Check if either operand is a domain variable
                operands = match.groups()
                is_domain = any(
                    any(dv in op.lower() for dv in _DOMAIN_VARS)
                    for op in operands if op
                )
                # Higher severity for domain variables
                actual_severity = severity if is_domain else Severity.LOW
                if not is_domain and severity == Severity.LOW:
                    continue  # Skip non-domain LOW findings

                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id=f"L0.{rule_id}",
                    message=message + (f" Variables: {', '.join(operands)}" if operands else ""),
                    file=rel_path, start_line=i,
                    severity=actual_severity, confidence=0.65,
                    blast_radius=BlastRadius.FUNCTION,
                    exploitability=0.3,
                    category=Category.CORRECTNESS,
                    cwe=cwe,
                    fix_suggestion="Use Math.multiplyExact() (throws on overflow) or BigInteger. Add range validation: if (qty > 0 && qty < MAX_QTY).",
                ))
                break  # One finding per line

    return findings


def scan_python_overflow(file_path: Path, repo_root: Path) -> List[Finding]:
    """Scan Python file for business arithmetic risks."""
    try:
        content = file_path.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return []

    rel_path = str(file_path.relative_to(repo_root))
    findings: List[Finding] = []
    lines = content.split('\n')

    for i, line in enumerate(lines, 1):
        for pattern, rule_id, severity, message, cwe in _PYTHON_OVERFLOW_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                # Check for range validation nearby
                has_validation = any(
                    re.search(v, line, re.IGNORECASE)
                    for v in [r'if\s+\w+\s*[<>=]', r'assert\s+\w+\s*[<>=]', r'min\s*\(', r'max\s*\(']
                )
                if not has_validation:
                    findings.append(Finding(
                        layer=LayerID.L0_FAST,
                        rule_id=f"L0.{rule_id}",
                        message=message,
                        file=rel_path, start_line=i,
                        severity=severity, confidence=0.5,
                        blast_radius=BlastRadius.FUNCTION,
                        exploitability=0.2,
                        category=Category.CORRECTNESS,
                        cwe=cwe,
                        fix_suggestion="Add range validation: if 0 < qty <= MAX_QTY. Use Decimal for financial calculations.",
                    ))
                    break

    return findings


def scan_repo_integer_overflow(repo_root: Path, max_files: int = 500) -> List[Finding]:
    """Scan repository for integer overflow risks.

    Detects:
      - Java: int/long multiplication without Math.multiplyExact
      - Java: chained addition without Math.addExact
      - Java: left shift without bounds check
      - Python: business arithmetic (qty*price) without range check
    """
    findings: List[Finding] = []
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                 "build", "dist", "target", ".loomscan-cache"}

    file_count = 0
    for p in repo_root.rglob("*"):
        if file_count >= max_files:
            break
        if not p.is_file():
            continue
        if any(part in skip_dirs for part in p.parts):
            continue

        ext = p.suffix.lower()
        if ext == '.java':
            findings.extend(scan_java_overflow(p, repo_root))
            file_count += 1
        elif ext == '.py':
            findings.extend(scan_python_overflow(p, repo_root))
            file_count += 1

    return findings
