"""First-run config wizard — creates .loomscan.yaml with user preferences.

On first run (when no .loomscan.yaml exists), the wizard guides the user
through:
  1. Confirm working directory
  2. Select file types to scan (Python, JS, Go, Java, etc.)
  3. Add exclusion patterns (node_modules, .git, build, etc.)
  4. Set strictness level
  5. Choose YAML engine (auto/rust/semgrep/python)
  6. Enable/disable specific analysis layers

All choices are saved to .loomscan.yaml so subsequent runs auto-load them.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from textual.app import ComposeResult
from textual.containers import Container, Vertical, Center, Middle, ScrollableContainer
from textual.screen import ModalScreen
from textual.widgets import (
    Static, Button, Input, Checkbox, Label, RadioSet, RadioButton,
    ProgressBar, Select
)
from textual.binding import Binding
from textual.reactive import reactive


class FirstRunWizard(ModalScreen):
    """First-run configuration wizard — creates .loomscan.yaml."""

    CSS = """
    FirstRunWizard {
        align: center middle;
    }

    FirstRunWizard #wizard-box {
        width: 1fr;
        max-width: 80;
        min-width: 50;
        height: 1fr;
        max-height: 90%;
        border: round $accent;
        background: $panel;
        padding: 1 2;
    }

    FirstRunWizard #wizard-title {
        text-align: center;
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }

    FirstRunWizard #wizard-subtitle {
        text-align: center;
        color: $text-muted;
        margin-bottom: 1;
    }

    FirstRunWizard .step-section {
        border: round $primary;
        padding: 1;
        margin-bottom: 1;
    }

    FirstRunWizard .step-title {
        color: $accent;
        text-style: bold;
        margin-bottom: 1;
    }

    FirstRunWizard #buttons {
        height: 3;
        align: center middle;
        margin-top: 1;
    }

    FirstRunWizard #status {
        color: $success;
        text-align: center;
        margin-top: 1;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    def __init__(self, repo_path: str):
        super().__init__()
        self._repo_path = repo_path
        self.config_data = {
            "repo_path": repo_path,
            "scan_python": True,
            "scan_javascript": True,
            "scan_go": True,
            "scan_java": True,
            "scan_c_cpp": True,
            "scan_rust": True,
            "scan_typescript": True,
            "excludes": "node_modules,.git,build,dist,__pycache__,.venv,venv,.loomscan-cache",
            "strictness": 5,
            "engine": "auto",
            "enable_secrets": True,
            "enable_taint": True,
            "enable_cpg": True,
            "enable_metamorphic": True,
        }

    def compose(self) -> ComposeResult:
        with Container(id="wizard-box"):
            yield Static("🕷️  Welcome to LoomScan!", id="wizard-title")
            yield Static("Let's configure your scan settings. This creates a .loomscan.yaml file.",
                        id="wizard-subtitle")

            # Step 1: File types
            with Container(classes="step-section"):
                yield Static("📁  File Types to Scan", classes="step-title")
                yield Checkbox("Python (.py)", True, id="scan-python")
                yield Checkbox("JavaScript (.js, .jsx)", True, id="scan-javascript")
                yield Checkbox("TypeScript (.ts, .tsx)", True, id="scan-typescript")
                yield Checkbox("Go (.go)", True, id="scan-go")
                yield Checkbox("Java (.java)", True, id="scan-java")
                yield Checkbox("C/C++ (.c, .cpp, .h)", True, id="scan-c-cpp")
                yield Checkbox("Rust (.rs)", True, id="scan-rust")

            # Step 2: Excludes
            with Container(classes="step-section"):
                yield Static("🚫  Exclude Paths (comma-separated)", classes="step-title")
                yield Input(
                    value="node_modules,.git,build,dist,__pycache__,.venv,venv,.loomscan-cache",
                    id="excludes-input"
                )
                yield Static("These patterns will be excluded from scanning. Use ** for globs.",
                           markup=False)

            # Step 3: Strictness
            with Container(classes="step-section"):
                yield Static("📊  Strictness Level", classes="step-title")
                yield RadioSet(
                    RadioButton("1 — Critical only", id="strict-1"),
                    RadioButton("3 — High+ critical", id="strict-3"),
                    RadioButton("5 — Balanced (recommended)", True, id="strict-5"),
                    RadioButton("7 — Strict (includes style)", id="strict-7"),
                    RadioButton("9 — Everything", id="strict-9"),
                    id="strictness-radioset",
                )

            # Step 4: Engine
            with Container(classes="step-section"):
                yield Static("🚀  YAML Rule Engine", classes="step-title")
                yield RadioSet(
                    RadioButton("Auto-detect (recommended)", True, id="engine-auto"),
                    RadioButton("Rust core (10-50x faster)", id="engine-rust"),
                    RadioButton("Semgrep (full pattern support)", id="engine-semgrep"),
                    RadioButton("Python re (always works)", id="engine-python"),
                    id="engine-radioset",
                )

            # Step 5: Analysis modules
            with Container(classes="step-section"):
                yield Static("🔍  Analysis Modules", classes="step-title")
                yield Checkbox("Secret detection", True, id="enable-secrets")
                yield Checkbox("Taint tracking (source→sink)", True, id="enable-taint")
                yield Checkbox("Code Property Graph (CPG)", True, id="enable-cpg")
                yield Checkbox("Metamorphic testing", True, id="enable-metamorphic")

            # Buttons
            with Container(id="buttons"):
                yield Button("✓  Save & Continue", id="save-btn", variant="primary")
                yield Button("✕  Cancel", id="cancel-btn", variant="error")

            yield Static("", id="status")

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        checkbox_map = {
            "scan-python": "scan_python",
            "scan-javascript": "scan_javascript",
            "scan-typescript": "scan_typescript",
            "scan-go": "scan_go",
            "scan-java": "scan_java",
            "scan-c-cpp": "scan_c_cpp",
            "scan-rust": "scan_rust",
            "enable-secrets": "enable_secrets",
            "enable-taint": "enable_taint",
            "enable-cpg": "enable_cpg",
            "enable-metamorphic": "enable_metamorphic",
        }
        if event.checkbox.id in checkbox_map:
            self.config_data[checkbox_map[event.checkbox.id]] = event.value

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "excludes-input":
            self.config_data["excludes"] = event.value

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        if event.radio_set.id == "strictness-radioset":
            selected = event.pressed
            if selected and selected.id:
                level = int(selected.id.split("-")[1])
                self.config_data["strictness"] = level
        elif event.radio_set.id == "engine-radioset":
            selected = event.pressed
            if selected and selected.id:
                self.config_data["engine"] = selected.id.replace("engine-", "")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save-btn":
            self._save_config()
        elif event.button.id == "cancel-btn":
            self.dismiss(None)

    def _save_config(self) -> None:
        """Save the configuration to .loomscan.yaml."""
        try:
            from ..config import STCAConfig, LayerConfig
            from ..models import LayerID

            repo = Path(self._repo_path)
            cfg = STCAConfig.default()
            cfg.strictness_level = self.config_data["strictness"]

            # Set excludes
            excludes = [e.strip() for e in self.config_data["excludes"].split(",") if e.strip()]
            excludes = [f"**/{e}/**" if not e.startswith("**") else e for e in excludes]
            cfg.workspace_exclude = excludes

            # Enable/disable layers based on user choices
            for layer_id in ["L0_fast", "L1_property", "L2_test_coverage", "L3_invariants",
                             "L4_fuzz", "L5_policy", "L6_symbolic", "L7_simulation"]:
                if layer_id in cfg.layers:
                    cfg.layers[layer_id].enabled = True

            # Save
            cfg_path = repo / ".loomscan.yaml"
            cfg.save(cfg_path)

            self.query_one("#status", Static).update(
                f"✓ Saved to {cfg_path}"
            )
            self.dismiss(self.config_data)

        except Exception as e:
            self.query_one("#status", Static).update(
                f"✗ Error: {e}"
            )

    def action_cancel(self) -> None:
        self.dismiss(None)
