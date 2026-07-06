"""Replace `_log_scanner_error(` with `self._scanner_error(` for all call
sites INSIDE the Orchestrator class body (lines after the class definition
and the _scanner_error method definition).

Leaves the module-level function definition (line ~16) and the call inside
Orchestrator._scanner_error (which forwards to the module function) intact.
"""
from pathlib import Path

PATH = Path("/home/z/my-project/stca-pipeline/stca/orchestrator.py")
src = PATH.read_text()
lines = src.splitlines(keepends=True)

# Find the line number where `_scanner_error` method definition ends
# (the line containing `_log_scanner_error(scanner_name, e, exc_info=exc_info,`)
# All calls AFTER that line should be replaced.
method_end_line = None
for i, line in enumerate(lines, 1):
    if "_log_scanner_error(scanner_name, e, exc_info=exc_info," in line:
        method_end_line = i
        break

if method_end_line is None:
    raise SystemExit("Could not find _scanner_error method body")

print(f"_scanner_error method body ends at line {method_end_line}")
print(f"Replacing all _log_scanner_error( calls after line {method_end_line}")

count = 0
for i in range(method_end_line, len(lines)):  # 0-indexed from method_end_line onwards
    if "_log_scanner_error(" in lines[i]:
        old = lines[i]
        lines[i] = lines[i].replace("_log_scanner_error(", "self._scanner_error(")
        if lines[i] != old:
            count += 1
            print(f"  line {i+1}: replaced")

PATH.write_text("".join(lines))
print(f"\nTotal replacements: {count}")
