"""Show context around each silent except:pass site for manual review."""
from __future__ import annotations
import re
from pathlib import Path

ROOT = Path("/home/z/my-project/stca-pipeline/stca")
PATTERN = re.compile(r'except\s+(\w+\s*(?:\([^)]*\))?\s*)?:\n(\s+)pass\b', re.MULTILINE)

for py in sorted(ROOT.rglob("*.py")):
    src = py.read_text()
    matches = list(PATTERN.finditer(src))
    if not matches:
        continue
    rel = py.relative_to(ROOT.parent)
    print(f"\n{'='*70}")
    print(f"FILE: {rel}")
    print(f"{'='*70}")
    for m in matches:
        line_no = src[:m.start()].count("\n") + 1
        # Get 6 lines before, 4 after
        lines = src.splitlines()
        start = max(0, line_no - 7)
        end = min(len(lines), line_no + 4)
        print(f"\n--- line {line_no} ---")
        for i in range(start, end):
            marker = ">>" if i + 1 == line_no else "  "
            print(f"{marker} {i+1:4d}: {lines[i]}")
