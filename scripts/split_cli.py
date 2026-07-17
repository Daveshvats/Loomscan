#!/usr/bin/env python3
"""v7.6: Split cli.py into a cli/ package with submodules.

Strategy:
1. Read cli.py
2. Adjust relative imports: `from .X` → `from ..X` (for loomscan-level imports)
3. Create cli/__init__.py with the main group + all legacy commands
4. Extract v7.4-v7.5 commands into cli/advanced.py and cli/security.py
5. Remove extracted commands from __init__.py
6. Import submodules at the end of __init__.py
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLI_FILE = ROOT / "loomscan" / "cli.py"
CLI_DIR = ROOT / "loomscan" / "cli"


def adjust_imports(content: str) -> str:
    """Adjust relative imports for package structure.
    
    In cli.py (a module), `from .models` means `loomscan.models`.
    In cli/__init__.py (a package), `from .models` means `loomscan.cli.models`.
    So we need to change `from .` to `from ..` for loomscan-level imports.
    """
    # Pattern: from .something import ...
    # Change to: from ..something import ...
    # But DON'T change `from . import` (which becomes `from .. import`)
    content = re.sub(
        r'^from \.([a-zA-Z_])',
        r'from ..\1',
        content,
        flags=re.MULTILINE
    )
    # Also handle: from . import X
    content = re.sub(
        r'^from \. import',
        r'from .. import',
        content,
        flags=re.MULTILINE
    )
    return content


def split_cli():
    """Main split function."""
    if not CLI_FILE.exists():
        print(f"ERROR: {CLI_FILE} not found")
        return False
    
    content = CLI_FILE.read_text()
    
    # Find the v7.4-v7.5 commands section (starts at the v7.4 comment block)
    v74_marker = "# =============================================================================\n# v7.4: New CLI commands"
    v75_marker = "# =============================================================================\n# v7.5: Restored modules"
    v75_gnn_marker = "# =============================================================================\n# v7.5: Real GNN-on-CPG"
    
    # Find split points
    v74_start = content.find(v74_marker)
    v75_start = content.find(v75_marker)
    v75_gnn_start = content.find(v75_gnn_marker)
    
    if v74_start == -1:
        print("ERROR: Could not find v7.4 marker")
        return False
    
    # Find the `if __name__` at the end
    main_block = content.rfind("if __name__")
    if main_block == -1:
        print("ERROR: Could not find if __name__ block")
        return False
    
    # Split content:
    # - main_part: everything up to v7.4 marker (the main group + legacy commands)
    # - advanced_part: v7.4 commands (learn, second-opinion, diff, gnn-score, gnn-train)
    # - security_part: v7.5 restored module commands (jsx-auth, stateful-pbt, multi-call)
    
    main_part = content[:v74_start]
    
    # Advanced commands: from v74_marker to v75_marker (or v75_gnn_marker if no v75_marker)
    adv_end = v75_start if v75_start != -1 else v75_gnn_start
    if adv_end == -1:
        adv_end = main_block
    advanced_part = content[v74_start:adv_end]
    
    # Security commands: from v75_marker to v75_gnn_marker (or main_block)
    sec_end = v75_gnn_start if v75_gnn_start != -1 else main_block
    if v75_start != -1:
        security_part = content[v75_start:sec_end if sec_end != -1 else main_block]
    else:
        security_part = ""
    
    # GNN commands: from v75_gnn_marker to main_block
    if v75_gnn_start != -1:
        gnn_part = content[v75_gnn_start:main_block]
    else:
        gnn_part = ""
    
    # The if __name__ block
    main_block_content = content[main_block:]
    
    # Create cli/ directory
    CLI_DIR.mkdir(exist_ok=True)
    
    # Adjust imports for all parts
    main_part = adjust_imports(main_part)
    advanced_part = adjust_imports(advanced_part)
    security_part = adjust_imports(security_part)
    gnn_part = adjust_imports(gnn_part)
    
    # Create cli/__init__.py (main group + legacy commands + submodule imports)
    init_content = main_part
    # Add submodule imports before the if __name__ block
    init_content += """
# =============================================================================
# v7.6: Import submodules to register their commands with the main group
# =============================================================================
from . import advanced  # noqa: F401 — learn, second-opinion, diff, gnn-score, gnn-train
from . import security  # noqa: F401 — jsx-auth, stateful-pbt, multi-call

"""
    init_content += main_block_content
    
    (CLI_DIR / "__init__.py").write_text(init_content)
    print(f"  Created cli/__init__.py ({len(init_content.splitlines())} lines)")
    
    # Create cli/advanced.py (v7.4 commands + GNN commands)
    if advanced_part or gnn_part:
        adv_content = '"""v7.6: Advanced CLI commands — active learning, GNN, differential analysis.\n\nExtracted from cli.py in v7.6.0 for maintainability.\n"""\n'
        adv_content += "from . import main  # noqa: F401 — registers with the Click group\n"
        adv_content += "from .. import __version__\n"  # needed by some commands
        adv_content += "\n"
        adv_content += advanced_part
        adv_content += "\n\n"
        adv_content += gnn_part
        
        (CLI_DIR / "advanced.py").write_text(adv_content)
        print(f"  Created cli/advanced.py ({len(adv_content.splitlines())} lines)")
    
    # Create cli/security.py (v7.5 restored module commands)
    if security_part:
        sec_content = '"""v7.6: Security CLI commands — JSX auth, stateful PBT, multi-call analysis.\n\nExtracted from cli.py in v7.6.0 for maintainability.\n"""\n'
        sec_content += "from . import main  # noqa: F401 — registers with the Click group\n"
        sec_content += "\n"
        sec_content += security_part
        
        (CLI_DIR / "security.py").write_text(sec_content)
        print(f"  Created cli/security.py ({len(sec_content.splitlines())} lines)")
    
    # Delete old cli.py
    CLI_FILE.unlink()
    print(f"  Deleted old cli.py")
    
    return True


if __name__ == "__main__":
    if split_cli():
        print("\n✅ cli.py split into cli/ package successfully")
    else:
        print("\n❌ Split failed")
