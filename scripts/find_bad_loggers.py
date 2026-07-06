"""Find files where the logger was inserted inside a docstring.

Detection: parse the file with ast and check if `logger` is a module-level
name. If not, the insertion was incorrect.
"""
from __future__ import annotations
import ast
from pathlib import Path

ROOT = Path("/home/z/my-project/stca-pipeline/stca")

bad = []
for py in sorted(ROOT.rglob("*.py")):
    src = py.read_text()
    if "logger = logging.getLogger" not in src:
        continue
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        rel = py.relative_to(ROOT.parent)
        bad.append((rel, f"SYNTAX ERROR: {e}"))
        continue
    # Check if `logger` is assigned at module level
    has_module_logger = False
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "logger":
                    has_module_logger = True
                    break
        if isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == "logger":
                has_module_logger = True
    if not has_module_logger:
        rel = py.relative_to(ROOT.parent)
        bad.append((rel, "logger is not at module level"))

print(f"Found {len(bad)} problematic files:")
for rel, reason in bad:
    print(f"  {rel}: {reason}")
