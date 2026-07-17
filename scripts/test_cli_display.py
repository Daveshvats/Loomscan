"""Test the CLI display renders without crashing."""
import sys, time
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console
from loomscan.cli_display import CLIDisplay

console = Console()
display = CLIDisplay(
    console=console,
    repo_path=str(Path(__file__).resolve().parent.parent),
    version="5.17.0",
    command="loomscan check --full --strictness 5",
)

# Simulate scan progress
display.start()
display.update_modules([
    "L0 Fast", "Secrets", "Taint", "CPG", "Metamorphic",
    "Code Quality", "Deadcode", "Nullness", "RCA",
    "Impact", "Duplicates", "Doc Audit", "Supply Chain"
], total=18)
display.update_files(0, 1248)
display.update_excludes(146, 34)

# Simulate stages
for i in range(1, 8):
    stages = ["L0 Fast", "Property Tests", "Coverage", "Data Flow Analysis",
              "Metamorphic", "FIS Brain", "AutoFix"]
    display.update_stage(stages[i-1], i, 7)
    display.update_files(i * 178, 1248, f"src/module_{i}/file.py")
    display.update_findings(
        critical=i * 2,
        high=i * 4,
        medium=i * 4,
        low=i * 6,
    )
    time.sleep(0.3)

# Finish
from pathlib import Path
display.finish(
    html_path=Path(__file__).resolve().parent.parent / ".loomscan-reports" / "report.html",
    sarif_path=Path(__file__).resolve().parent.parent / ".loomscan-reports" / "result.sarif",
    json_path=Path(__file__).resolve().parent.parent / ".loomscan-reports" / "result.json",
)
print("\n✓ Display test complete!")
