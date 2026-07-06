"""Survey all .py files under stca/ for silent `except Exception: pass`
and `except: pass` patterns. Reports counts per file with line numbers.

This is a discovery script — does not modify files.
"""
from __future__ import annotations
import re
from pathlib import Path

ROOT = Path("/home/z/my-project/stca-pipeline/stca")

# Match `except ...:\n<indent>pass` (any indentation on the pass line,
# but commonly 4-24 spaces). We capture the line number of the except.
PATTERN = re.compile(
    r'except\s+(\w+\s*(?:\([^)]*\))?\s*)?:\n(\s+)pass\b',
    re.MULTILINE,
)

results = []
total = 0
for py in sorted(ROOT.rglob("*.py")):
    src = py.read_text()
    matches = list(PATTERN.finditer(src))
    if not matches:
        continue
    lines = []
    for m in matches:
        line_no = src[:m.start()].count("\n") + 1
        lines.append(line_no)
    results.append((py, lines))
    total += len(lines)

print(f"=== Silent except:pass patterns per file ===")
print(f"Total files with silent patterns: {len(results)}")
print(f"Total silent patterns: {total}")
print()
for py, lines in results:
    rel = py.relative_to(ROOT.parent)
    print(f"  {rel}: {len(lines)} site(s) at lines {lines[:10]}{'...' if len(lines) > 10 else ''}")
