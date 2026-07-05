"""Metamorphic testing — oracle-free bug detection.

The oracle problem: for many functions, you can't say what the "correct"
output is. (E.g., what's the correct output of a recommendation engine? a
hash function? a sort?)

Metamorphic testing sidesteps this: instead of checking the output, check
RELATIONS between outputs. If `sort(x)` is correct, then `sort(x) == sort(x ++ x)[:len(x)]`.

Metamorphic relations (MRs) are properties that hold across transformations
of the input. If an MR is violated, you have a bug — without needing to know
the correct output.

This module:
  - Auto-generates MRs based on function signatures and patterns
  - Runs them with Hypothesis-generated inputs
  - Reports violations as findings (not crashes)

Common MRs we generate:
  - sort: sort(x ++ x)[:len(x)] == sort(x)
  - hash: hash(x) == hash(x)  (deterministic)
  - hash: hash(x ++ y) ≠ hash(y ++ x)  (unless commutative)
  - parse-serialize round-trip: serialize(parse(x)) == x  (for valid x)
  - identity: f(x) == f(x)  (deterministic)
  - monotonicity: if x < y then f(x) <= f(y)  (for monotone fns)
  - distributivity: f(x + y) == f(x) + f(y)  (for linear fns)
  - idempotence: f(f(x)) == f(x)  (for idempotent fns)
"""
from __future__ import annotations

import ast
import importlib
import inspect
import sys
import subprocess
import textwrap
from pathlib import Path
from typing import List, Optional, Tuple, Callable
from dataclasses import dataclass


@dataclass
class MetamorphicViolation:
    """A metamorphic relation was violated — likely a bug."""
    function: str
    relation: str  # name of the MR
    description: str
    input_summary: str
    file: str


# Heuristics for detecting function categories from their name/body
def _classify_function(name: str, body: str) -> List[str]:
    """Return list of MR categories that might apply to this function."""
    cats = []
    name_lower = name.lower()
    if "sort" in name_lower or "order" in name_lower:
        cats.append("sort")
    if "hash" in name_lower or "digest" in name_lower or "checksum" in name_lower:
        cats.append("hash")
    if "parse" in name_lower and ("serialize" in body or "to_string" in body or "dumps" in body):
        cats.append("parse_round_trip")
    if "normalize" in name_lower or "canonical" in name_lower:
        cats.append("idempotence")
    if "abs" in name_lower or "length" in name_lower or "size" in name_lower:
        cats.append("non_negative")
    if "add" in name_lower or "sum" in name_lower or "concat" in name_lower:
        cats.append("commutative")
    if "max" in name_lower or "min" in name_lower:
        cats.append("monotonic")
    # default: identity (determinism) applies to every function
    cats.append("identity")
    return cats


# Metamorphic relations: each generates (input1, input2, predicate) given a function
METAMORPHIC_RELATIONS = {
    "identity": {
        "name": "Determinism",
        "description": "f(x) == f(x) for any x",
        "arity": 1,
    },
    "sort": {
        "name": "Sort idempotence",
        "description": "sort(sort(x)) == sort(x)",
        "arity": 1,
    },
    "hash": {
        "name": "Hash determinism",
        "description": "hash(x) == hash(x)",
        "arity": 1,
    },
    "parse_round_trip": {
        "name": "Parse/serialize round-trip",
        "description": "serialize(parse(x)) == x for valid x",
        "arity": 1,
    },
    "idempotence": {
        "name": "Idempotence",
        "description": "f(f(x)) == f(x)",
        "arity": 1,
    },
    "non_negative": {
        "name": "Non-negative output",
        "description": "f(x) >= 0 for any x",
        "arity": 1,
    },
    "commutative": {
        "name": "Commutativity",
        "description": "f(x, y) == f(y, x)",
        "arity": 2,
    },
}


def generate_mr_test_code(func_name: str, func_signature: str,
                          category: str, module_path: str) -> Optional[str]:
    """Generate Hypothesis test code for a metamorphic relation."""
    if category == "identity":
        return textwrap.dedent(f"""
            from hypothesis import given, strategies as st, assume, settings
            from {module_path} import {func_name}

            @settings(max_examples=50)
            @given(st.integers(min_value=-1000, max_value=1000))
            def test_mr_identity_{func_name}(x):
                '''Metamorphic: f(x) == f(x) (determinism).'''
                assert {func_name}(x) == {func_name}(x)
        """).strip()

    if category == "sort":
        return textwrap.dedent(f"""
            from hypothesis import given, strategies as st, settings
            from {module_path} import {func_name}

            @settings(max_examples=50)
            @given(st.lists(st.integers(min_value=-100, max_value=100), min_size=0, max_size=20))
            def test_mr_sort_idempotence_{func_name}(x):
                '''Metamorphic: sort(sort(x)) == sort(x).'''
                once = {func_name}(x)
                twice = {func_name}(once)
                assert once == twice, f"Sort not idempotent: {{once}} != {{twice}}"

            @settings(max_examples=50)
            @given(st.lists(st.integers(min_value=-100, max_value=100), min_size=0, max_size=20))
            def test_mr_sort_determinism_{func_name}(x):
                '''Metamorphic: sort(x ++ x)[:len(x)] == sort(x).'''
                once = {func_name}(x)
                doubled = {func_name}(x + x)[:len(x)] if len(x) > 0 else []
                assert once == doubled, f"Sort scaling failed: {{once}} != {{doubled}}"
        """).strip()

    if category == "hash":
        return textwrap.dedent(f"""
            from hypothesis import given, strategies as st, settings
            from {module_path} import {func_name}

            @settings(max_examples=50)
            @given(st.text(min_size=0, max_size=100))
            def test_mr_hash_determinism_{func_name}(x):
                '''Metamorphic: hash(x) == hash(x) (determinism).'''
                assert {func_name}(x) == {func_name}(x)

            @settings(max_examples=50)
            @given(st.text(min_size=1, max_size=100))
            def test_mr_hash_unequal_{func_name}(x):
                '''Metamorphic: hash(x + "a") != hash(x + "b") (in general).'''
                # not always true, but violations are interesting
                a = {func_name}(x + "a")
                b = {func_name}(x + "b")
                # we don't fail, but report if always equal (likely bug)
                if a == b:
                    import warnings
                    warnings.warn(f"hash collision: {{x!r}}+a == {{x!r}}+b")
        """).strip()

    if category == "idempotence":
        return textwrap.dedent(f"""
            from hypothesis import given, strategies as st, settings
            from {module_path} import {func_name}

            @settings(max_examples=50)
            @given(st.text(min_size=0, max_size=100))
            def test_mr_idempotence_{func_name}(x):
                '''Metamorphic: f(f(x)) == f(x) (idempotence).'''
                once = {func_name}(x)
                twice = {func_name}(once)
                assert once == twice, f"Not idempotent: {{once!r}} != {{twice!r}}"
        """).strip()

    if category == "non_negative":
        return textwrap.dedent(f"""
            from hypothesis import given, strategies as st, settings
            from {module_path} import {func_name}

            @settings(max_examples=50)
            @given(st.text(min_size=0, max_size=100))
            def test_mr_non_negative_{func_name}(x):
                '''Metamorphic: f(x) >= 0 for any x.'''
                result = {func_name}(x)
                if isinstance(result, (int, float)):
                    assert result >= 0, f"Negative result for non-negative function: {{result}}"
        """).strip()

    if category == "commutative":
        return textwrap.dedent(f"""
            from hypothesis import given, strategies as st, settings
            from {module_path} import {func_name}

            @settings(max_examples=50)
            @given(st.integers(min_value=-100, max_value=100),
                   st.integers(min_value=-100, max_value=100))
            def test_mr_commutative_{func_name}(x, y):
                '''Metamorphic: f(x, y) == f(y, x) (commutativity).'''
                assert {func_name}(x, y) == {func_name}(y, x), \\
                    f"Not commutative: f({{x}},{{y}}) != f({{y}},{{x}})"
        """).strip()

    return None


def discover_testable_functions(file_path: Path) -> List[Tuple[str, str, List[str]]]:
    """Find functions in a file and classify them for MR testing.

    Returns list of (function_name, function_signature, mr_categories).
    """
    if not file_path.exists() or file_path.suffix != ".py":
        return []
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        return []

    results: List[Tuple[str, str, List[str]]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name.startswith("_"):
            continue
        body = ast.unparse(node)
        cats = _classify_function(node.name, body)
        results.append((node.name, ast.unparse(node.args), cats))
    return results


def run_metamorphic_tests(file_path: Path, repo_root: Path = None) -> List[MetamorphicViolation]:
    """Generate and run metamorphic tests for the functions in a file.

    Returns a list of violations (likely bugs).
    """
    functions = discover_testable_functions(file_path)
    if not functions:
        return []

    rel_path = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    module_path = rel_path.replace("/", ".").replace(".py", "").lstrip(".")

    # generate a test file
    test_code_parts = []
    test_names = []
    for func_name, sig, cats in functions:
        for cat in cats:
            test_code = generate_mr_test_code(func_name, sig, cat, module_path)
            if test_code:
                test_code_parts.append(test_code)
                test_names.append(f"test_mr_{cat}_{func_name}")

    if not test_code_parts:
        return []

    test_file = (repo_root or file_path.parent) / ".stca-cache" / "metamorphic" / f"test_{file_path.stem}_mr.py"
    test_file.parent.mkdir(parents=True, exist_ok=True)
    test_file.write_text("\n\n".join(test_code_parts), encoding="utf-8")

    # run pytest on the test file
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", str(test_file), "-v", "--tb=short",
             "--maxfail=5"],
            capture_output=True, text=True, check=False, timeout=30,
            cwd=str(repo_root or file_path.parent),
        )
    except Exception:
        return []

    # parse failures
    violations: List[MetamorphicViolation] = []
    for line in proc.stdout.splitlines():
        if "FAILED" in line or "AssertionError" in line:
            # extract function name from the failure
            for func_name, _, cats in functions:
                for cat in cats:
                    test_name = f"test_mr_{cat}_{func_name}"
                    if test_name in line:
                        violations.append(MetamorphicViolation(
                            function=func_name,
                            relation=METAMORPHIC_RELATIONS.get(cat, {}).get("name", cat),
                            description=METAMORPHIC_RELATIONS.get(cat, {}).get("description", ""),
                            input_summary=line[:200],
                            file=rel_path,
                        ))
                        break
    return violations
