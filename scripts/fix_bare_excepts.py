#!/usr/bin/env python3
"""v7.3.4: Replace bare 'except:' with 'except Exception:' in loomscan/ Python files.

Bare except clauses catch SystemExit, KeyboardInterrupt, and GeneratorExit —
which can hide failures and break Ctrl+C. Replacing with 'except Exception:'
is the standard safe fix (Exception doesn't catch the three control-flow
exceptions above).

Skips:
  - lines inside string literals (heuristic: line contains a quote before `except:`)
  - the l8_autofix.py file (which deliberately documents the bare-except pattern)
  - multi_language_advanced.py generated code strings (the bare except is in
    generated test code, not LoomScan's own code)
"""
import re
from pathlib import Path

# Files to skip (deliberate bare-except usage)
SKIP_FILES = {
    "loomscan/layers/l8_autofix.py",  # documents the bare-except fix pattern
    "loomscan/multi_language_advanced.py",  # generates test code with bare except
}

# Pattern: bare 'except:' (not 'except Exception:' or 'except SomeError:')
# Match 'except:' at end of line or followed by space/comment
BARE_EXCEPT_RE = re.compile(r'\bexcept\s*:')


def is_in_string(line: str, pos: int) -> bool:
    """Heuristic: check if position `pos` in `line` is inside a string literal."""
    # Count unescaped quotes before pos
    before = line[:pos]
    # Simple heuristic: if odd number of unescaped single or double quotes, we're in a string
    singles = 0
    doubles = 0
    i = 0
    while i < len(before):
        c = before[i]
        if c == '\\' and i + 1 < len(before):
            i += 2  # skip escaped char
            continue
        if c == '"':
            doubles += 1
        elif c == "'":
            singles += 1
        i += 1
    return (singles % 2 == 1) or (doubles % 2 == 1)


def fix_file(path: Path) -> int:
    """Replace bare 'except:' with 'except Exception:'. Returns count of replacements."""
    try:
        text = path.read_text(encoding='utf-8')
    except Exception:
        return 0

    lines = text.split('\n')
    fixed = 0
    new_lines = []
    for line in lines:
        m = BARE_EXCEPT_RE.search(line)
        if m and not is_in_string(line, m.start()):
            # Replace 'except:' with 'except Exception:'
            new_line = line[:m.start()] + 'except Exception:' + line[m.end():]
            new_lines.append(new_line)
            fixed += 1
        else:
            new_lines.append(line)

    if fixed > 0:
        path.write_text('\n'.join(new_lines), encoding='utf-8')
    return fixed


def main():
    root = Path(__file__).resolve().parent.parent / "loomscan"
    total_fixed = 0
    files_fixed = 0
    for py_file in root.rglob("*.py"):
        rel = str(py_file.relative_to(Path(__file__).resolve().parent.parent))
        if rel in SKIP_FILES:
            print(f"  SKIP {rel}")
            continue
        n = fix_file(py_file)
        if n > 0:
            print(f"  FIXED {rel}: {n} bare except → except Exception:")
            total_fixed += n
            files_fixed += 1
    print(f"\nTotal: {total_fixed} bare except clauses fixed across {files_fixed} files")


if __name__ == "__main__":
    main()
