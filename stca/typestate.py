"""Typestate analysis — detect state machine violations.

Many bugs are state machine violations:
  - Calling .charge() before .authorize()
  - Using a connection after .close()
  - Reading from a file before .open()
  - Calling .send() after .shutdown()
  - Double-charging a payment
  - Using a session after .logout()

Real typestate analysis (Plaid, Mungo, Frama-C) requires type system support.
We do a pragmatic version: track method calls on objects and flag violations
of common protocol patterns.

Patterns we detect:
  - close-then-use: .close() followed by any other method call on same object
  - authorize-then-charge: .charge() called on a payment without prior .authorize()
  - open-then-read: read/write before .open()
  - send-after-shutdown: .send() after .shutdown()
  - double-action: same method called twice without reset

This is a lightweight version of what research tools like Mungo (Java) and
Plaid (Rust) do at the type-system level.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import List, Dict, Tuple, Set
from dataclasses import dataclass


# Protocol definitions: (type_pattern, method_order_constraints)
# Each constraint: (required_prior, method) — method requires required_prior to be called first
PROTOCOLS = {
    "file_like": {
        "methods": {"open", "read", "write", "close", "seek", "tell"},
        "requires_prior": {
            "read": "open",
            "write": "open",
            "seek": "open",
            "tell": "open",
        },
        "terminal": {"close"},  # no method should be called after close
    },
    "connection_like": {
        "methods": {"connect", "execute", "commit", "rollback", "close"},
        "requires_prior": {
            "execute": "connect",
            "commit": "connect",
            "rollback": "connect",
        },
        "terminal": {"close"},
    },
    "payment_like": {
        "methods": {"authorize", "charge", "refund", "void"},
        "requires_prior": {
            "charge": "authorize",
            "refund": "charge",
            "void": "authorize",
        },
        "terminal": {"void", "refund"},
    },
    "session_like": {
        "methods": {"login", "get", "post", "put", "delete", "logout"},
        "requires_prior": {
            "get": "login",
            "post": "login",
            "put": "login",
            "delete": "login",
        },
        "terminal": {"logout"},
    },
    "transaction_like": {
        "methods": {"begin", "execute", "commit", "rollback"},
        "requires_prior": {
            "execute": "begin",
            "commit": "begin",
            "rollback": "begin",
        },
        "terminal": {"commit", "rollback"},
    },
}


@dataclass
class TypestateViolation:
    """A detected state machine violation."""
    file: str
    line: int
    object_name: str
    protocol: str
    violation: str  # 'close_then_use' | 'requires_prior' | 'double_action'
    description: str
    cwe: str = "CWE-664"  # improper control of a resource through its lifetime


def analyze_typestate(file_path: Path) -> List[TypestateViolation]:
    """Analyze a Python file for typestate violations."""
    if not file_path.exists() or file_path.suffix != ".py":
        return []
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        return []

    violations: List[TypestateViolation] = []

    # For each function, track method calls on each variable
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        func_violations = _analyze_function_typestate(node, str(file_path))
        violations.extend(func_violations)

    return violations


def _analyze_function_typestate(func_node: ast.FunctionDef,
                                 file_path: str) -> List[TypestateViolation]:
    """Track method calls on variables within a single function."""
    violations: List[TypestateViolation] = []

    # state: variable_name → list of (method, line) called on it
    var_calls: Dict[str, List[Tuple[str, int]]] = {}

    # walk ALL call nodes in the function (not just ast.Expr-wrapped ones)
    for stmt in ast.walk(func_node):
        if not isinstance(stmt, ast.Call):
            continue
        if not isinstance(stmt.func, ast.Attribute):
            continue

        obj_node = stmt.func.value
        method_name = stmt.func.attr

        if isinstance(obj_node, ast.Name):
            var_name = obj_node.id
        else:
            continue

        # find matching protocol
        protocol = _match_protocol(method_name)
        if not protocol:
            continue

        proto_name, proto_def = protocol
        history = var_calls.setdefault(var_name, [])

        # check requires_prior
        if method_name in proto_def.get("requires_prior", {}):
            required = proto_def["requires_prior"][method_name]
            if not any(m == required for m, _ in history):
                violations.append(TypestateViolation(
                    file=file_path,
                    line=stmt.lineno,
                    object_name=var_name,
                    protocol=proto_name,
                    violation="requires_prior",
                    description=f"{var_name}.{method_name}() called without prior {required}() — {proto_name} protocol violation",
                    cwe="CWE-664",
                ))

        # check terminal (close-then-use)
        if proto_def.get("terminal") and history:
            for prev_method, prev_line in history:
                if prev_method in proto_def["terminal"]:
                    violations.append(TypestateViolation(
                        file=file_path,
                        line=stmt.lineno,
                        object_name=var_name,
                        protocol=proto_name,
                        violation="close_then_use",
                        description=f"{var_name}.{method_name}() called after {prev_method}() at line {prev_line} — use after terminal operation",
                        cwe="CWE-416",  # use after free / similar
                    ))
                    break

        # check double-action (same method called twice, not allowed)
        if method_name in proto_def.get("terminal", set()):
            for prev_method, prev_line in history:
                if prev_method == method_name:
                    violations.append(TypestateViolation(
                        file=file_path,
                        line=stmt.lineno,
                        object_name=var_name,
                        protocol=proto_name,
                        violation="double_action",
                        description=f"{var_name}.{method_name}() called twice (first at line {prev_line}) — double-{method_name} is likely a bug",
                        cwe="CWE-675",  # multiple operations on single resource
                    ))
                    break

        history.append((method_name, stmt.lineno))

    return violations


def _match_protocol(method_name: str):
    """Find a protocol that includes this method."""
    for proto_name, proto_def in PROTOCOLS.items():
        if method_name in proto_def["methods"]:
            return (proto_name, proto_def)
    return None
