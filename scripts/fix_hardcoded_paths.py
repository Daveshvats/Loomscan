#!/usr/bin/env python3
"""v7.5.4: Fix ALL hardcoded /home/z/my-project paths in scripts/ and tests/.

Replaces /home/z/my-project with dynamic path resolution.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def fix_file(filepath: Path) -> int:
    """Fix hardcoded paths in a file. Returns count of replacements."""
    try:
        content = filepath.read_text()
    except Exception:
        return 0

    original = content
    fixes = 0

    # Pattern 1: sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    # Replace with: sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    # But for tests/ files, parent.parent is the project root
    # For scripts/ files, parent.parent is also the project root
    content = re.sub(
        r'sys\.path\.insert\(0,\s*["\']/home/z/my-project["\']\)',
        'sys.path.insert(0, str(Path(__file__).resolve().parent.parent))',
        content
    )

    # Pattern 2: Path("/home/z/my-project/loomscan/...")
    # Replace with: Path(__file__).resolve().parent.parent / "loomscan" / ...
    content = re.sub(
        r'Path\(["\']/home/z/my-project/loomscan/rules/packs/([^"\']+)["\']\)',
        r'Path(__file__).resolve().parent.parent / "loomscan" / "rules" / "packs" / "\1"',
        content
    )

    # Pattern 3: Path(__file__).resolve().parent.parent / "loomscan"
    content = re.sub(
        r'Path\(["\']/home/z/my-project/loomscan["\']\)',
        'Path(__file__).resolve().parent.parent / "loomscan"',
        content
    )

    # Pattern 4: Path(__file__).resolve().parent.parent
    content = re.sub(
        r'Path\(["\']/home/z/my-project["\']\)',
        'Path(__file__).resolve().parent.parent',
        content
    )

    # Pattern 5: str(Path(__file__).resolve().parent.parent) as a string arg (e.g., repo_path=str(Path(__file__).resolve().parent.parent))
    content = re.sub(
        r'str(Path(__file__).resolve().parent.parent)',
        'str(Path(__file__).resolve().parent.parent)',
        content
    )

    # Pattern 6: Path(__file__).resolve().parent.parent / ".loomscan-reports" / "..."
    content = re.sub(
        r'Path\(["\']/home/z/my-project/\.loomscan-reports/([^"\']+)["\']\)',
        r'Path(__file__).resolve().parent.parent / ".loomscan-reports" / "\1"',
        content
    )

    # Pattern 7: Path('/home/z/my-project/tests/...')
    content = re.sub(
        r"Path\(['/\"]home/z/my-project/tests/([^'\"]+)['\"]\)",
        r'Path(__file__).resolve().parent.parent / "tests" / "\1"',
        content
    )

    # Pattern 8: str(Path(__file__).resolve().parent.parent) in string literals (old name)
    content = re.sub(
        r"str(Path(__file__).resolve().parent.parent)",
        'str(Path(__file__).resolve().parent.parent)',
        content
    )

    # Pattern 9: str(Path(__file__).resolve().parent.parent) in string literals (embedded in other strings)
    # This handles cases like: "import sys; sys.path.insert(0, str(Path(__file__).resolve().parent.parent)); "
    content = re.sub(
        r"str(Path(__file__).resolve().parent.parent)",
        'str(Path(__file__).resolve().parent.parent)',
        content
    )

    if content != original:
        # Count how many lines changed
        old_lines = original.split('\n')
        new_lines = content.split('\n')
        for i, (old, new) in enumerate(zip(old_lines, new_lines)):
            if old != new:
                fixes += 1
        filepath.write_text(content)

    return fixes


def main():
    files_to_fix = []
    for pattern in ['scripts/*.py', 'tests/*.py']:
        files_to_fix.extend(Path(ROOT).glob(pattern))

    total_fixes = 0
    files_fixed = 0
    for f in sorted(files_to_fix):
        n = fix_file(f)
        if n > 0:
            print(f"  FIXED {f.relative_to(ROOT)}: {n} line(s)")
            total_fixes += n
            files_fixed += 1

    print(f"\nTotal: {total_fixes} lines fixed across {files_fixed} files")

    # Verify no more hardcoded paths
    remaining = []
    for f in sorted(files_to_fix):
        content = f.read_text()
        if str(Path(__file__).resolve().parent.parent) in content:
            for i, line in enumerate(content.split('\n'), 1):
                if str(Path(__file__).resolve().parent.parent) in line:
                    remaining.append(f"  {f.relative_to(ROOT)}:{i}: {line.strip()[:80]}")

    if remaining:
        print(f"\n⚠️  {len(remaining)} lines still have hardcoded paths:")
        for r in remaining[:10]:
            print(r)
    else:
        print("\n✅ No hardcoded /home/z/my-project paths remaining")


if __name__ == "__main__":
    main()
