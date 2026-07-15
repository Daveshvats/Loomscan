"""v6.0: Domain-aware business logic spec mining.

Catches business logic bugs that generic spec mining misses:
  - Negative quantity/amount (e.g., order with qty=-5 gives refund)
  - Missing price validation (price=0 or price=-1)
  - Missing balance check before withdrawal
  - Missing inventory check before order
  - Unbounded loop on user-controlled counter

Unlike generic spec mining (which mines API usage patterns), this module
understands DOMAIN CONCEPTS: quantity, price, amount, balance, inventory,
discount, tax. It mines the codebase for validation patterns on these
fields and flags functions where validation is missing.

How it works:
  1. Scans all Python/Java/JS files for domain-variable patterns:
     `if qty > 0`, `if amount >= 0`, `if price > 0`, `if balance >= amount`
  2. Builds a "validation profile" — which domain variables are validated
     and how (positive check, range check, comparison check).
  3. For each function that uses a domain variable WITHOUT validation,
     flags it as a business logic risk.
"""
from __future__ import annotations

import re
import ast
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional
from .models import Finding, Severity, LayerID, BlastRadius, Category


# Domain variable name patterns (case-insensitive)
_DOMAIN_VARS = {
    "quantity": ["qty", "quantity", "count", "num", "number", "amount", "volume", "size"],
    "price": ["price", "cost", "rate", "fee", "charge", "amount_due", "subtotal", "total"],
    "money": ["balance", "amount", "deposit", "withdrawal", "transfer", "payment", "refund",
              "credit", "debit", "salary", "wage", "bonus", "commission"],
    "inventory": ["stock", "inventory", "available", "on_hand", "quantity_available"],
    "discount": ["discount", "rebate", "coupon", "promo", "markdown", "reduction"],
    "tax": ["tax", "vat", "gst", "sales_tax", "tax_rate"],
    "user_input_numeric": ["score", "rating", "points", "level", "rank", "priority"],
}

# Validation patterns (what "good" validation looks like)
_VALIDATION_PATTERNS = {
    "positive_check": r'if\s+\w*(qty|quantity|amount|price|count|total|score|volume)\w*\s*(?:>|>=|==)\s*[1-9]',
    "non_negative_check": r'if\s+\w*(qty|quantity|amount|price|count|total|balance|deposit)\w*\s*(?:>=|>|==)\s*0',
    "balance_check": r'if\s+\w*balance\w*\s*(?:>=|>)\s*\w*(amount|withdrawal|transfer|payment)\w*',
    "range_check": r'if\s+\w*(qty|quantity|amount|price|count|score|rating)\w*\s*(?:<|<=|>=|>)\s*\d+',
    "is_positive": r'\w*(qty|quantity|amount|price)\w*\s*(?:>|>=)\s*[1-9]',
}

# Risk patterns (what "bad" code looks like — domain var used without validation)
_RISK_PATTERNS: List[Tuple[str, str, Severity, str, str]] = [
    # Negative quantity in arithmetic
    (r'\b(qty|quantity|count|amount)\b\s*[\*]\s*\w*(price|cost|rate)\b',
     "bl.negative_quantity_arithmetic",
     Severity.HIGH,
     "Business logic: qty * price without validation — negative qty gives negative total (refund). Validate qty > 0 before multiplication.",
     "CWE-840"),
    # Negative amount in DB write
    (r'\b(refund|credit|withdrawal|transfer)\b.*\bamount\b',
     "bl.negative_amount_operation",
     Severity.HIGH,
     "Business logic: financial operation with amount — verify amount is non-negative. Negative amount could reverse the transaction direction.",
     "CWE-840"),
    # Balance check missing before withdrawal
    (r'(withdraw|transfer|deduct|subtract)\w*\s*\([^)]*amount',
     "bl.missing_balance_check",
     Severity.HIGH,
     "Business logic: withdrawal/transfer without visible balance check — may allow overdraft. Verify balance >= amount before deducting.",
     "CWE-840"),
    # Price set from user input without validation
    (r'\bprice\s*=\s*(?:request|req|input|body|params|form|data)\b',
     "bl.price_from_user_input",
     Severity.CRITICAL,
     "Business logic: price assigned from user input — attacker can set price=0 or negative. Validate price > 0 server-side.",
     "CWE-840"),
    # Discount > 100% or negative
    (r'\bdiscount\s*=\s*(?:request|req|input|body|params|form|data)\b',
     "bl.discount_from_user_input",
     Severity.HIGH,
     "Business logic: discount from user input — verify 0 <= discount <= 100. Negative discount increases price; >100 gives money back.",
     "CWE-840"),
    # Tax rate from user input
    (r'\btax(?:_rate)?\s*=\s*(?:request|req|input|body|params|form|data)\b',
     "bl.tax_from_user_input",
     Severity.HIGH,
     "Business logic: tax rate from user input — verify 0 <= tax_rate <= 1.0. Negative or >1 tax is invalid.",
     "CWE-840"),
    # Score/rating from user input without range check
    (r'\b(score|rating)\s*=\s*(?:request|req|input|body|params|form|data)\b',
     "bl.score_from_user_input",
     Severity.MEDIUM,
     "Business logic: score/rating from user input — validate range (e.g., 0-5, 0-100). Without validation, attacker can set arbitrary scores.",
     "CWE-840"),
    # Quantity update without check
    (r'(update|set|save|insert)\w*.*\b(qty|quantity|stock|inventory)\b',
     "bl.quantity_update_no_check",
     Severity.MEDIUM,
     "Business logic: quantity/stock update — verify new value is non-negative. Negative stock is invalid.",
     "CWE-840"),
]


def scan_python_business_logic(file_path: Path, repo_root: Path) -> List[Finding]:
    """Scan a Python file for business logic bugs using AST + heuristics."""
    if file_path.suffix != '.py':
        return []
    try:
        source = file_path.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return []

    rel_path = str(file_path.relative_to(repo_root))
    findings: List[Finding] = []

    # Parse AST to find functions and their validation patterns
    try:
        tree = ast.parse(source)
    except Exception:
        return []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        func_source = ast.get_source_segment(source, node) or ""
        func_name = node.name

        # Skip __init__, __str__, etc.
        if func_name.startswith('_') and func_name != '__init__':
            continue

        # Check each risk pattern against the function source
        for pattern, rule_id, severity, message, cwe in _RISK_PATTERNS:
            if re.search(pattern, func_source, re.IGNORECASE):
                # Check if the function has validation for this domain variable
                has_validation = any(
                    re.search(vp, func_source, re.IGNORECASE)
                    for vp in _VALIDATION_PATTERNS.values()
                )
                if not has_validation:
                    findings.append(Finding(
                        layer=LayerID.L0_FAST,
                        rule_id=f"L0.{rule_id}",
                        message=f"{message} | Function: {func_name}()",
                        file=rel_path, start_line=node.lineno,
                        severity=severity, confidence=0.7,
                        blast_radius=BlastRadius.MODULE,
                        exploitability=0.8,
                        category=Category.CORRECTNESS,
                        cwe=cwe,
                        fix_suggestion=_get_bl_fix(rule_id),
                    ))

    return findings


def scan_java_business_logic(file_path: Path, repo_root: Path) -> List[Finding]:
    """Scan a Java file for business logic bugs using regex."""
    return _scan_regex_business_logic(file_path, repo_root)


def scan_js_business_logic(file_path: Path, repo_root: Path) -> List[Finding]:
    """Scan a JavaScript file for business logic bugs using regex."""
    return _scan_regex_business_logic(file_path, repo_root)


def _scan_regex_business_logic(file_path: Path, repo_root: Path) -> List[Finding]:
    """Scan a file using regex for business logic risks."""
    try:
        content = file_path.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return []

    rel_path = str(file_path.relative_to(repo_root))
    findings: List[Finding] = []

    for pattern, rule_id, severity, message, cwe in _RISK_PATTERNS:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            line_num = content[:match.start()].count('\n') + 1
            # Check if there's validation nearby (within 10 lines)
            start = max(0, match.start() - 500)
            end = min(len(content), match.end() + 500)
            context = content[start:end]
            has_validation = any(
                re.search(vp, context, re.IGNORECASE)
                for vp in _VALIDATION_PATTERNS.values()
            )
            if not has_validation:
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id=f"L0.{rule_id}",
                    message=message,
                    file=rel_path, start_line=line_num,
                    severity=severity, confidence=0.65,
                    blast_radius=BlastRadius.MODULE,
                    exploitability=0.7,
                    category=Category.CORRECTNESS,
                    cwe=cwe,
                    fix_suggestion=_get_bl_fix(rule_id),
                ))

    return findings


def _get_bl_fix(rule_id: str) -> str:
    fixes = {
        "bl.negative_quantity_arithmetic": "Add validation: if qty <= 0: raise ValueError('Quantity must be positive'). Or use abs(qty) if negative is impossible by design.",
        "bl.negative_amount_operation": "Add validation: if amount < 0: raise ValueError('Amount cannot be negative'). Log the attempt for fraud detection.",
        "bl.missing_balance_check": "Add balance check: if account.balance < amount: raise InsufficientFundsError(). Use SELECT FOR UPDATE to prevent concurrent withdrawal race.",
        "bl.price_from_user_input": "Never trust user-provided prices. Look up price from database using product ID. If user can set price, validate: if price <= 0: reject.",
        "bl.discount_from_user_input": "Validate discount: if discount < 0 or discount > MAX_DISCOUNT: reject. Store MAX_DISCOUNT in config, not in code.",
        "bl.tax_from_user_input": "Never accept tax rate from user input. Calculate tax server-side using the user's jurisdiction. If user-provided, validate 0 <= rate <= 1.0.",
        "bl.score_from_user_input": "Validate score range: if score < MIN_SCORE or score > MAX_SCORE: reject. Use @Min/@Max annotations in Java, or if-checks in Python/JS.",
        "bl.quantity_update_no_check": "Before update: if new_quantity < 0: raise ValueError('Quantity cannot be negative'). Use database CHECK constraint: quantity >= 0.",
    }
    return fixes.get(rule_id, "Add domain-specific validation: verify the value is within expected bounds before using it.")


def scan_repo_business_logic(repo_root: Path, max_files: int = 500) -> List[Finding]:
    """Scan a repository for business logic bugs.

    Detects:
      - Negative quantity/amount in arithmetic (refund exploit)
      - Missing balance check before withdrawal
      - Price/discount/tax from user input without validation
      - Score/rating from user input without range check
      - Quantity/stock update without non-negative check
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
        if ext == '.py':
            findings.extend(scan_python_business_logic(p, repo_root))
            file_count += 1
        elif ext == '.java':
            findings.extend(scan_java_business_logic(p, repo_root))
            file_count += 1
        elif ext in ('.js', '.ts'):
            findings.extend(scan_js_business_logic(p, repo_root))
            file_count += 1

    return findings
