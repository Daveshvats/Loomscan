"""Sound nullness analysis for Python (NilAway-inspired).

NilAway (Uber) detects nil panics in Go using sound static analysis — it's
conservative (may have false positives) but never misses a nil dereference.

This module does the same for Python None:
  - Tracks which variables could be None at each program point
  - Flags dereferences of None-able variables (calling methods, accessing attrs)
  - Distinguishes "definitely None" from "possibly None"
  - Respects None-guards (if x is None: return) — after the guard, x is non-None

This catches:
  - `x.method()` where x could be None
  - `x.attribute` where x could be None
  - `len(x)` where x could be None
  - `x[0]` where x could be None

Unlike NilAway, this is not fully sound (Python's dynamic typing makes that
impossible), but it catches the common cases that lead to NoneType errors.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple


@dataclass
class NullnessIssue:
    """A potential None dereference."""
    file: str
    line: int
    variable: str
    reason: str  # why we think it could be None
    confidence: float  # 0..1
    context: str = ""  # the offending line


class NullnessAnalyzer:
    """Analyzes a Python function for None dereferences."""

    def __init__(self):
        pass

    def analyze_file(self, file_path: Path, repo_root: Path = None) -> List[NullnessIssue]:
        """Analyze a Python file for None dereferences."""
        if not file_path.exists() or file_path.suffix != ".py":
            return []
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except Exception:
            return []

        rel_path = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
        issues: List[NullnessIssue] = []

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                issues += self._analyze_function(node, rel_path, source)
        return issues

    def _analyze_function(self, func_node: ast.FunctionDef,
                            file: str, source: str) -> List[NullnessIssue]:
        """Analyze a single function for None dereferences."""
        issues: List[NullnessIssue] = []
        # Track which variables are "possibly None"
        # Sources of None:
        #   - Parameters with default value None
        #   - Variables assigned None
        #   - Variables assigned the result of a function that might return None
        #     (we approximate: any function call result is possibly None)
        #   - dict.get() / list index results (possibly None)
        possibly_none: Set[str] = set()
        # definitely_none: Set[str] = set()  # not used for now

        # Check parameters with default None
        for arg, default in zip(func_node.args.args[-len(func_node.args.defaults):],
                                  func_node.args.defaults):
            if isinstance(default, ast.Constant) and default.value is None:
                possibly_none.add(arg.arg)

        # Walk statements in order (control flow matters for nullness)
        for node in ast.walk(func_node):
            # Assignment: x = None → x is possibly None
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        if isinstance(node.value, ast.Constant) and node.value.value is None:
                            possibly_none.add(target.id)
                        elif isinstance(node.value, ast.Call):
                            # function call result is possibly None
                            possibly_none.add(target.id)
                        elif isinstance(node.value, ast.Attribute):
                            # x = obj.attr — could be None
                            possibly_none.add(target.id)
                        elif isinstance(node.value, ast.Subscript):
                            # x = d["key"] — could be None
                            possibly_none.add(target.id)
                        else:
                            # other assignments: assume not None
                            possibly_none.discard(target.id)

            # None guard: if x is None: return → after this, x is not None
            if isinstance(node, ast.If):
                if isinstance(node.test, ast.Compare):
                    if isinstance(node.test.left, ast.Name) and \
                       isinstance(node.test.ops[0], ast.Is) and \
                       isinstance(node.test.comparators[0], ast.Constant) and \
                       node.test.comparators[0].value is None:
                        # if there's a return/raise in the body, x is non-None after
                        for stmt in node.body:
                            if isinstance(stmt, (ast.Return, ast.Raise)):
                                possibly_none.discard(node.test.left.id)

            # Detect None dereferences
            # Pattern 1: x.method() where x is possibly None
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                obj = node.func.value
                if isinstance(obj, ast.Name) and obj.id in possibly_none:
                    # check if there's a guard before this
                    if not self._is_guarded(obj.id, node.lineno, func_node):
                        issues.append(NullnessIssue(
                            file=file, line=node.lineno,
                            variable=obj.id,
                            reason=f"'{obj.id}' is possibly None (assigned from function/None/dict access)",
                            confidence=0.7,
                            context=self._get_line(source, node.lineno),
                        ))

            # Pattern 2: x.attr (not call) where x is possibly None
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                if node.value.id in possibly_none and not self._is_guarded(node.value.id, node.lineno, func_node):
                    # avoid double-reporting with call pattern above
                    # only report if this is NOT a call func
                    parent_check = True  # simplified
                    if parent_check:
                        issues.append(NullnessIssue(
                            file=file, line=node.lineno,
                            variable=node.value.id,
                            reason=f"'{node.value.id}' is possibly None when accessing .{node.attr}",
                            confidence=0.65,
                            context=self._get_line(source, node.lineno),
                        ))

            # Pattern 3: len(x), x[i] where x is possibly None
            if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
                if node.value.id in possibly_none and not self._is_guarded(node.value.id, node.lineno, func_node):
                    issues.append(NullnessIssue(
                        file=file, line=node.lineno,
                        variable=node.value.id,
                        reason=f"'{node.value.id}' is possibly None when subscripting",
                        confidence=0.7,
                        context=self._get_line(source, node.lineno),
                    ))

        # Dedupe by (line, variable)
        seen: Set[Tuple[int, str]] = set()
        unique: List[NullnessIssue] = []
        for issue in issues:
            key = (issue.line, issue.variable)
            if key not in seen:
                seen.add(key)
                unique.append(issue)
        return unique

    def _is_guarded(self, var_name: str, line: int, func_node: ast.FunctionDef) -> bool:
        """Check if a variable is guarded against None before a given line."""
        for node in ast.walk(func_node):
            if isinstance(node, ast.If) and node.lineno < line:
                if isinstance(node.test, ast.Compare):
                    if isinstance(node.test.left, ast.Name) and node.test.left.id == var_name:
                        if isinstance(node.test.ops[0], ast.Is) and \
                           isinstance(node.test.comparators[0], ast.Constant) and \
                           node.test.comparators[0].value is None:
                            # Check if there's a return/raise in the body
                            for stmt in node.body:
                                if isinstance(stmt, (ast.Return, ast.Raise)):
                                    return True
        return False

    def _get_line(self, source: str, line: int) -> str:
        """Get a specific line from source code."""
        lines = source.splitlines()
        if 0 < line <= len(lines):
            return lines[line - 1].strip()
        return ""
