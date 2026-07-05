"""Business logic understanding.

Extracts and verifies domain-level rules: authorization matrix, business
state machines (order/payment/user/subscription), invariants from asserts
and raise-if checks, and detects drift between docstring claims and code.

This module deliberately avoids heavyweight NLP — every extractor uses
regex + AST heuristics that work across Python and JS.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


# =============================================================================
# Auth rule data model
# =============================================================================

@dataclass
class AuthRule:
    """One authorization rule extracted from the codebase."""
    file: str
    line: int
    rule_type: str        # decorator | inline_check | hoc | route_guard
    pattern: str          # e.g. "@login_required", "@PreAuthorize('hasRole(...)'"
    roles: List[str] = field(default_factory=list)
    function: str = ""
    description: str = ""


@dataclass
class AuthViolation:
    """A detected auth violation."""
    file: str
    line: int
    rule_id: str
    severity: str
    description: str
    fix: str = ""
    cwe: str = "CWE-862"


# =============================================================================
# Auth matrix extractor
# =============================================================================

_PY_DECORATORS = [
    (r"@login_required", ["user"]),
    (r"@permission_required\s*\(\s*['\"]([^'\"]+)['\"]", None),  # roles captured
    (r"@require_roles\s*\(\s*['\"]([^'\"]+)['\"]", None),
    (r"@admin_required", ["admin"]),
    (r"@staff_required", ["staff"]),
    (r"@authenticated", ["user"]),
    (r"@requires_auth", ["user"]),
]

_JS_DECORATORS = [
    (r"@(?:RequireAuth|WithAuth|Authenticated)", ["user"]),
    (r"@(?:Admin|AdminOnly|RequireAdmin)", ["admin"]),
    (r"@(?:Role|RequireRole)\s*\(\s*['\"]([^'\"]+)['\"]", None),
    (r"@(?:Permission|RequirePermission)\s*\(\s*['\"]([^'\"]+)['\"]", None),
]

# Inline checks: `if not current_user: raise Unauthorized`
_PY_INLINE_CHECKS = [
    (r"if\s+(?:not\s+)?current_user\s*(?:is\s+(?:not\s+)?None)?\s*[:=]", "user"),
    (r"require_role\s*\(\s*['\"]([^'\"]+)['\"]", None),
    (r"check_permission\s*\(\s*['\"]([^'\"]+)['\"]", None),
    (r"raise\s+(?:Unauthorized|Forbidden|NotAuthenticated)", None),
]


class AuthMatrixExtractor:
    """Extract auth rules from Python decorators, JS decorators, and inline checks."""

    def extract_from_file(self, file_path: Path) -> List[AuthRule]:
        if not file_path.exists():
            return []
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []
        rules: List[AuthRule] = []
        ext = file_path.suffix.lower()
        if ext == ".py":
            rules.extend(self._extract_py_decorators(source, str(file_path)))
            rules.extend(self._extract_inline_checks(source, str(file_path)))
        elif ext in {".js", ".jsx", ".ts", ".tsx"}:
            rules.extend(self._extract_js_decorators(source, str(file_path)))
        return rules

    def _extract_py_decorators(self, source: str, file: str) -> List[AuthRule]:
        out: List[AuthRule] = []
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            for pat, base_roles in _PY_DECORATORS:
                m = re.search(pat, line)
                if not m:
                    continue
                roles = base_roles if base_roles else ([m.group(1)] if m.lastindex else [])
                out.append(AuthRule(
                    file=file, line=i, rule_type="decorator",
                    pattern=pat, roles=roles,
                    description=f"@-decorator '{line.strip()}' requires role(s): {roles}"))
        return out

    def _extract_js_decorators(self, source: str, file: str) -> List[AuthRule]:
        out: List[AuthRule] = []
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            for pat, base_roles in _JS_DECORATORS:
                m = re.search(pat, line)
                if not m:
                    continue
                roles = base_roles if base_roles else ([m.group(1)] if m.lastindex else [])
                out.append(AuthRule(
                    file=file, line=i, rule_type="decorator",
                    pattern=pat, roles=roles,
                    description=f"JS decorator '{line.strip()}' requires role(s): {roles}"))
        return out

    def _extract_inline_checks(self, source: str, file: str) -> List[AuthRule]:
        out: List[AuthRule] = []
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            for pat, base_role in _PY_INLINE_CHECKS:
                m = re.search(pat, line)
                if not m:
                    continue
                roles = [base_role] if base_role else (
                    [m.group(1)] if m.lastindex else ["user"])
                out.append(AuthRule(
                    file=file, line=i, rule_type="inline_check",
                    pattern=pat, roles=roles,
                    description=f"Inline auth check at line {i}: '{line.strip()}'"))
        return out


# =============================================================================
# Auth violation detector
# =============================================================================

_SENSITIVE_PATTERNS = [
    (r"\b(?:delete|remove|destroy|purge|wipe)\w*\s*\(", "delete"),
    (r"\b(?:admin|root|sudo)\w*\s*\(", "admin"),
    (r"\b(?:refund|chargeback|reverse_payment)\w*\s*\(", "payment"),
    (r"\b(?:update_role|grant|revoke|change_password|reset_password)\w*\s*\(", "privilege"),
    (r"\b(?:export|download_all|bulk)\w*\s*\(", "data-export"),
]


class AuthViolationDetector:
    """Detect sensitive actions that lack an auth check in the same function."""

    def __init__(self, rules: Optional[List[AuthRule]] = None) -> None:
        self.rules = rules or []

    def analyze_file(self, file_path: Path) -> List[AuthViolation]:
        if not file_path.exists() or file_path.suffix != ".py":
            return []
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except Exception:
            return []
        file_str = str(file_path)
        # map function lineno → has_auth (from extracted rules)
        auth_lines: Set[int] = {r.line for r in self.rules if r.file == file_str}
        out: List[AuthViolation] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            func_start = node.lineno
            func_end = max((n.lineno for n in ast.walk(node) if hasattr(n, "lineno")),
                            default=node.lineno)
            # function has auth if any rule line is within its body OR decorators
            has_auth = any(func_start - 2 <= r.line <= func_end + 1
                            for r in self.rules if r.file == file_str)
            if has_auth:
                continue
            # scan body for sensitive calls
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                    method = sub.func.attr
                elif isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                    method = sub.func.id
                else:
                    continue
                for pat, kind in _SENSITIVE_PATTERNS:
                    if re.search(pat, method):
                        out.append(AuthViolation(
                            file=file_str, line=sub.lineno,
                            rule_id=f"AUTH-NO-CHECK-{kind.upper()}",
                            severity="high",
                            description=f"Sensitive {kind} action '{method}()' in '{node.name}()' has no auth check",
                            fix=f"Add @login_required or an inline role check to {node.name}()",
                            cwe="CWE-862"))
                        break
        return out


# =============================================================================
# Business state machine analyzer
# =============================================================================

_BUSINESS_SMS: Dict[str, dict] = {
    "order": {
        "states": ["created", "pending_payment", "paid", "shipped", "delivered", "cancelled", "refunded"],
        "transitions": {
            "created": ["pending_payment", "cancelled"],
            "pending_payment": ["paid", "cancelled"],
            "paid": ["shipped", "refunded", "cancelled"],
            "shipped": ["delivered"],
            "delivered": ["refunded"],
        },
        "method_to_state": {
            "create": "created", "pay": "paid", "ship": "shipped",
            "deliver": "delivered", "cancel": "cancelled", "refund": "refunded",
        },
    },
    "payment": {
        "states": ["initiated", "authorized", "captured", "refunded", "voided", "failed"],
        "transitions": {
            "initiated": ["authorized", "failed", "voided"],
            "authorized": ["captured", "voided", "refunded"],
            "captured": ["refunded"],
        },
        "method_to_state": {
            "authorize": "authorized", "capture": "captured",
            "refund": "refunded", "void": "voided", "fail": "failed",
        },
    },
    "user": {
        "states": ["registered", "active", "suspended", "deactivated", "deleted"],
        "transitions": {
            "registered": ["active", "deleted"],
            "active": ["suspended", "deactivated"],
            "suspended": ["active", "deactivated"],
            "deactivated": ["active", "deleted"],
        },
        "method_to_state": {
            "register": "registered", "activate": "active",
            "suspend": "suspended", "deactivate": "deactivated",
            "delete": "deleted",
        },
    },
    "subscription": {
        "states": ["trialing", "active", "past_due", "canceled", "expired"],
        "transitions": {
            "trialing": ["active", "canceled", "expired"],
            "active": ["past_due", "canceled"],
            "past_due": ["active", "canceled", "expired"],
        },
        "method_to_state": {
            "start_trial": "trialing", "activate": "active",
            "mark_past_due": "past_due", "cancel": "canceled", "expire": "expired",
        },
    },
}


@dataclass
class BusinessSMViolation:
    file: str
    line: int
    rule_id: str
    severity: str
    description: str
    fix: str = ""


class BusinessStateMachineAnalyzer:
    """Detect invalid state transitions in order/payment/user/subscription flows."""

    def analyze_file(self, file_path: Path) -> List[BusinessSMViolation]:
        if not file_path.exists() or file_path.suffix != ".py":
            return []
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except Exception:
            return []
        out: List[BusinessSMViolation] = []
        file_str = str(file_path)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # Heuristic: identify resource type by function name (e.g., "refund_order")
            for kind, sm in _BUSINESS_SMS.items():
                if kind in node.name.lower():
                    out.extend(self._check_function_transitions(node, kind, sm, file_str))
        return out

    def _check_function_transitions(self, func: ast.FunctionDef, kind: str,
                                       sm: dict, file: str) -> List[BusinessSMViolation]:
        out: List[BusinessSMViolation] = []
        # find calls like `entity.<state_method>()` and ensure transition is valid
        last_state: Optional[str] = None
        for sub in ast.walk(func):
            if not isinstance(sub, ast.Call) or not isinstance(sub.func, ast.Attribute):
                continue
            method = sub.func.attr
            new_state = sm["method_to_state"].get(method)
            if not new_state:
                continue
            if last_state is not None:
                valid = sm["transitions"].get(last_state, [])
                if new_state not in valid:
                    out.append(BusinessSMViolation(
                        file=file, line=sub.lineno,
                        rule_id=f"BIZ-{kind.upper()}-INVALID-TRANSITION",
                        severity="high",
                        description=f"Invalid {kind} transition: {last_state} → {new_state} "
                                    f"(valid: {valid})",
                        fix=f"Add guard: if {kind}.state != '{last_state}': raise"))
            last_state = new_state
        return out


# =============================================================================
# Invariant miner
# =============================================================================

@dataclass
class Invariant:
    file: str
    line: int
    function: str
    expr: str
    source: str  # 'assert' | 'if-raise'
    description: str


class InvariantMiner:
    """Mine invariants from `assert` statements and `if cond: raise` patterns."""

    def mine_file(self, file_path: Path) -> List[Invariant]:
        if not file_path.exists() or file_path.suffix != ".py":
            return []
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except Exception:
            return []
        out: List[Invariant] = []
        file_str = str(file_path)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for sub in ast.walk(node):
                if isinstance(sub, ast.Assert):
                    try:
                        expr = ast.unparse(sub.test) if hasattr(ast, "unparse") else "<assert>"
                    except Exception:
                        expr = "<assert>"
                    out.append(Invariant(
                        file=file_str, line=sub.lineno, function=node.name,
                        expr=expr, source="assert",
                        description=f"assert {expr}"))
                elif (isinstance(sub, ast.If)
                      and sub.orelse == []
                      and len(sub.body) == 1
                      and isinstance(sub.body[0], ast.Raise)):
                    try:
                        expr = ast.unparse(sub.test) if hasattr(ast, "unparse") else "<cond>"
                    except Exception:
                        expr = "<cond>"
                    out.append(Invariant(
                        file=file_str, line=sub.lineno, function=node.name,
                        expr=f"not ({expr})", source="if-raise",
                        description=f"if {expr}: raise"))
        return out


# =============================================================================
# Doc drift analyzer
# =============================================================================

@dataclass
class DocDrift:
    file: str
    line: int
    function: str
    claim: str
    mismatch: str


class DocDriftAnalyzer:
    """Detect drift between docstring claims and actual code behavior."""

    _PARAM_RE = re.compile(r":param\s+(\w+):")
    _RETURN_RE = re.compile(r":returns?:")
    _RAISE_RE = re.compile(r":raises?\s+(\w+):")

    def analyze_file(self, file_path: Path) -> List[DocDrift]:
        if not file_path.exists() or file_path.suffix != ".py":
            return []
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except Exception:
            return []
        out: List[DocDrift] = []
        file_str = str(file_path)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            doc = ast.get_docstring(node)
            if not doc:
                continue
            # Check :param mentions match actual params
            doc_params = set(self._PARAM_RE.findall(doc))
            actual_params = {a.arg for a in node.args.args + node.args.kwonlyargs}
            for p in doc_params - actual_params:
                out.append(DocDrift(
                    file=file_str, line=node.lineno, function=node.name,
                    claim=f":param {p}:",
                    mismatch=f"Docstring documents param '{p}' but function does not declare it"))
            # Check :returns presence if function actually returns a value
            doc_has_return = bool(self._RETURN_RE.search(doc))
            actual_returns = any(isinstance(n, ast.Return) and n.value is not None
                                  for n in ast.walk(node))
            if doc_has_return and not actual_returns:
                out.append(DocDrift(
                    file=file_str, line=node.lineno, function=node.name,
                    claim=":returns:",
                    mismatch="Docstring documents a return value but function never returns one"))
            if actual_returns and not doc_has_return and not node.name.startswith("_"):
                out.append(DocDrift(
                    file=file_str, line=node.lineno, function=node.name,
                    claim="<missing :returns:>",
                    mismatch="Function returns a value but docstring has no :returns:"))
            # Check :raises mentions match actual raises
            doc_raises = set(self._RAISE_RE.findall(doc))
            actual_raises: Set[str] = set()
            for n in ast.walk(node):
                if isinstance(n, ast.Raise) and n.exc:
                    if isinstance(n.exc, ast.Call) and isinstance(n.exc.func, ast.Name):
                        actual_raises.add(n.exc.func.id)
                    elif isinstance(n.exc, ast.Name):
                        actual_raises.add(n.exc.id)
            for r in actual_raises - doc_raises:
                out.append(DocDrift(
                    file=file_str, line=node.lineno, function=node.name,
                    claim=f"<missing :raises {r}:>",
                    mismatch=f"Function raises {r} but docstring does not document it"))
        return out
