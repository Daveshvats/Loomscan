"""Command palette — search-filterable command list.

Inspired by MiMoCode's dialog-command.tsx — a popup overlay with:
  - Search input at top
  - Categorized command list
  - Keyboard navigation (up/down/enter)
  - Selected item highlighted with accent color

All LoomScan CLI commands are registered here so users can access them
from the TUI without memorizing CLI flags.
"""
from __future__ import annotations

from typing import Optional, Callable

from textual.app import ComposeResult
from textual.containers import Container, Vertical
from textual.screen import ModalScreen
from textual.widgets import Static, Input, ListView, ListItem, Label
from textual.binding import Binding
from textual.reactive import reactive


class CommandItem:
    """A single command in the palette."""
    def __init__(self, cmd_id: str, title: str, description: str,
                 category: str, keybind: str = ""):
        self.cmd_id = cmd_id
        self.title = title
        self.description = description
        self.category = category
        self.keybind = keybind


# All LoomScan commands accessible from the TUI
COMMANDS: list[CommandItem] = [
    # === Scan ===
    CommandItem("scan", "Scan Repository", "Start a full scan", "Scan", "ctrl+s"),
    CommandItem("scan_diff", "Scan Diff", "Scan only git diff changes", "Scan"),
    CommandItem("quickstart", "Quickstart", "Run first-time setup + scan", "Scan"),

    # === Results ===
    CommandItem("results", "View Results", "Show last scan findings", "View"),
    CommandItem("export_sarif", "Export SARIF", "Export results as SARIF", "View", "e"),
    CommandItem("export_json", "Export JSON", "Export results as JSON", "View", "j"),
    CommandItem("dashboard", "Dashboard", "Generate HTML dashboard", "View"),
    CommandItem("summary", "Summary", "Show grouped finding summary", "View"),

    # === Config ===
    CommandItem("settings", "Settings", "Open settings panel", "Config"),
    CommandItem("init", "Init Config", "Create .loomscan.yaml", "Config"),
    CommandItem("wizard", "Config Wizard", "Run first-run setup wizard", "Config"),
    CommandItem("strictness", "Strictness", "Set strictness level (1-9)", "Config"),
    CommandItem("engine", "Switch Engine", "Change YAML rule engine", "Config"),
    CommandItem("cd", "Change Directory", "Change working directory", "Config"),

    # === Analysis ===
    CommandItem("taint", "Taint Analysis", "Run taint tracking", "Analysis"),
    CommandItem("cpg", "CPG Queries", "Run code property graph queries", "Analysis"),
    CommandItem("metamorphic", "Metamorphic", "Run metamorphic tests", "Analysis"),
    CommandItem("differential", "Differential", "Run differential tests", "Analysis"),
    CommandItem("nullness", "Nullness", "Run null deref analysis", "Analysis"),
    CommandItem("consistency", "Consistency", "Check pattern consistency", "Analysis"),
    CommandItem("deadcode", "Dead Code", "Find dead code", "Analysis"),
    CommandItem("typestate", "Typestate", "Check state machine violations", "Analysis"),
    CommandItem("contracts", "Contracts", "Check pre/post conditions", "Analysis"),
    CommandItem("rca", "Root Cause", "Find root causes", "Analysis"),
    CommandItem("impact", "Impact Analysis", "Show blast radius", "Analysis"),
    CommandItem("architecture", "Architecture", "Enforce architecture rules", "Analysis"),

    # === Security ===
    CommandItem("secrets", "Secret Scan", "Scan for secrets", "Security"),
    CommandItem("flawfinder", "Flawfinder", "C/C++ dangerous functions", "Security"),
    CommandItem("malicious", "Malicious Patterns", "Detect malicious code", "Security"),
    CommandItem("pii", "PII Detection", "Find PII data", "Security"),
    CommandItem("missing_patches", "Missing Patches", "Check unpatched CVEs", "Security"),
    CommandItem("toxicity", "Toxicity", "Code toxicity analysis", "Security"),
    CommandItem("ffi_check", "FFI Check", "Foreign function interface check", "Security"),

    # === Quality ===
    CommandItem("code_quality", "Code Quality", "Run quality checks", "Quality"),
    CommandItem("duplicates", "Duplicates", "Find duplicate code", "Quality"),
    CommandItem("doc_audit", "Doc Audit", "Audit documentation", "Quality"),
    CommandItem("business_logic", "Business Logic", "BL detection", "Quality"),
    CommandItem("crypto", "Crypto Audit", "Cryptographic checks", "Quality"),
    CommandItem("concurrency", "Concurrency", "Concurrency checks", "Quality"),

    # === Supply Chain ===
    CommandItem("supply_chain", "Supply Chain", "Dependency health check", "Supply Chain"),
    CommandItem("sbom", "SBOM", "Generate SBOM", "Supply Chain"),
    CommandItem("maven_cve", "Maven CVEs", "Java dependency CVEs", "Supply Chain"),

    # === Infrastructure ===
    CommandItem("iac", "IaC Scan", "Terraform/Docker/K8s check", "Infra"),
    CommandItem("config_scan", "Config Scan", "Configuration file check", "Infra"),
    CommandItem("modern", "Modern Attacks", "Modern attack patterns", "Infra"),

    # === System ===
    CommandItem("doctor", "Doctor", "Check system health", "System"),
    CommandItem("install_tools", "Install Tools", "Install external tools", "System"),
    CommandItem("gate", "Quality Gate", "Run quality gate", "System"),
    CommandItem("fix", "Auto-Fix", "Apply auto-fixes", "System"),
    CommandItem("monorepo", "Monorepo", "Scan monorepo workspaces", "System"),
    CommandItem("watch", "Watch", "Watch for file changes", "System"),
    CommandItem("lsp", "LSP Server", "Start LSP server", "System"),

    # === Rules ===
    CommandItem("mine", "Mine Rules", "Auto-mine rules from git history", "Rules"),
    CommandItem("spec", "Spec Mining", "Mine API usage patterns", "Rules"),
    CommandItem("rule_lint", "Rule Lint", "Lint custom rules", "Rules"),
    CommandItem("playground", "Playground", "Rule playground", "Rules"),
    CommandItem("bot", "PR Bot", "GitHub PR comment bot", "Rules"),
    CommandItem("submit", "Submit Pack", "Submit a rule pack", "Rules"),

    # === Session ===
    CommandItem("help", "Help", "Show help", "Session"),
    CommandItem("quit", "Quit", "Exit LoomScan", "Session", "q"),
]


class CommandPalette(ModalScreen):
    """Command palette popup — search and run any LoomScan command."""

    CSS = """
    CommandPalette {
        align: center middle;
    }

    CommandPalette #palette-box {
        width: 70;
        max-width: 90;
        height: auto;
        max-height: 80%;
        border: round $accent;
        background: $panel;
        padding: 1;
    }

    CommandPalette #palette-header {
        text-align: center;
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }

    CommandPalette #palette-search {
        margin-bottom: 1;
    }

    CommandPalette #palette-list {
        height: auto;
        max-height: 30;
    }

    CommandPalette .cmd-category {
        color: $primary;
        text-style: bold;
        padding: 1 0 0 1;
    }

    CommandPalette ListItem {
        padding: 0 1;
    }

    CommandPalette ListItem:hover {
        background: $boost;
    }

    CommandPalette #palette-footer {
        text-align: center;
        color: $text-muted;
        margin-top: 1;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
    ]

    def __init__(self):
        super().__init__()
        self._all_commands = COMMANDS
        self._filtered: list[CommandItem] = list(COMMANDS)

    def compose(self) -> ComposeResult:
        with Container(id="palette-box"):
            yield Static("Commands", id="palette-header")
            yield Input(placeholder="Search commands... (type to filter)",
                       id="palette-search")
            yield ListView(id="palette-list")
            yield Static("↑↓ navigate  •  enter select  •  esc close",
                        id="palette-footer")

    def on_mount(self) -> None:
        self._populate_list()
        self.query_one("#palette-search", Input).focus()

    def _populate_list(self, filter_text: str = "") -> None:
        """Populate the command list, optionally filtered."""
        lv = self.query_one("#palette-list", ListView)
        lv.clear()

        if filter_text:
            ft = filter_text.lower()
            self._filtered = [c for c in self._all_commands
                            if ft in c.title.lower() or ft in c.cmd_id.lower()
                            or ft in c.description.lower() or ft in c.category.lower()]
        else:
            self._filtered = list(self._all_commands)

        # Group by category
        categories: dict[str, list[CommandItem]] = {}
        for cmd in self._filtered:
            if cmd.category not in categories:
                categories[cmd.category] = []
            categories[cmd.category].append(cmd)

        for category, items in categories.items():
            cat_item = ListItem(Label(f"── {category} ──"), classes="cmd-category")
            cat_item.disabled = True
            lv.append(cat_item)
            for cmd in items:
                keybind_str = f" [{cmd.keybind}]" if cmd.keybind else ""
                label_text = f"  {cmd.title}{keybind_str}  —  {cmd.description}"
                item = ListItem(Label(label_text), id=f"cmd-{cmd.cmd_id}")
                lv.append(item)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "palette-search":
            self._populate_list(event.value)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Handle command selection."""
        if event.item.id and event.item.id.startswith("cmd-"):
            cmd_id = event.item.id[4:]
            self.dismiss(cmd_id)

    def action_dismiss(self) -> None:
        self.dismiss(None)
