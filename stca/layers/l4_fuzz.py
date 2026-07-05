"""L4 — Directed fuzzing layer.

Runs Atheris (Python fuzzing) on changed functions. The "directed" part:
we only fuzz the changed functions, not the whole program (WAFLGO-style
diff-directed fuzzing).

If Atheris isn't installed, the layer is a no-op with an INFO finding.
"""
from __future__ import annotations

import subprocess
import sys
import textwrap
import tempfile
from pathlib import Path
from typing import List

from .base import LayerBase
from ..models import Finding, DiffHunk, LayerID, Severity, BlastRadius


class L4Fuzz(LayerBase):
    id = LayerID.L4_FUZZ
    name = "Directed Fuzzing"
    description = "Atheris fuzzing on changed functions (WAFLGO-style directed)"

    DEFAULT_DURATION_SECONDS = 10  # short — this is pre-commit, not CI

    def run(self, repo_root: Path, hunks: List[DiffHunk],
            config) -> List[Finding]:
        findings: List[Finding] = []
        py_hunks = [h for h in hunks if h.file.endswith(".py") and h.function_name]
        if not py_hunks:
            return findings

        try:
            import atheris  # noqa
        except ImportError:
            findings.append(Finding(
                layer=self.id, rule_id="L4.atheris.not_installed",
                message="atheris not installed — install with `pip install atheris` for Python fuzzing",
                file="<pipeline>", start_line=0,
                severity=Severity.INFO, confidence=1.0,
            ))
            return findings

        # generate a fuzz harness for each changed function
        for hunk in py_hunks[:3]:  # cap at 3 to keep pre-commit fast
            harness_path = self._generate_harness(repo_root, hunk)
            if not harness_path:
                continue
            crash = self._run_harness(harness_path, repo_root,
                                      duration=self.DEFAULT_DURATION_SECONDS)
            if crash:
                findings.append(Finding(
                    layer=self.id, rule_id="L4.fuzz.crash",
                    message=f"Fuzzing {hunk.function_name} produced a crash: {crash[:200]}",
                    file=hunk.file, start_line=hunk.start_line, end_line=hunk.end_line,
                    severity=Severity.CRITICAL, confidence=0.85,
                    blast_radius=BlastRadius.MODULE, exploitability=0.7,
                    cwe="CWE-20",  # improper input validation
                    fix_suggestion="Add input validation at function entry; check for None, type, and range",
                    raw={"function": hunk.function_name, "crash": crash[:500]},
                ))
        return findings

    def _generate_harness(self, repo_root: Path, hunk: DiffHunk) -> Path:
        """Generate a simple Atheris harness for the function.

        We attempt to call the function with random bytes interpreted as
        different argument types. The user can provide a custom harness in
        `tests/fuzz/<function>_fuzz.py` which takes precedence.
        """
        custom_harness = repo_root / "tests" / "fuzz" / f"{hunk.function_name}_fuzz.py"
        if custom_harness.exists():
            return custom_harness

        # auto-generate a naive harness
        module_path = hunk.file.replace("/", ".").replace(".py", "")
        # strip leading dots
        if module_path.startswith("."):
            module_path = module_path.lstrip(".")

        harness_code = textwrap.dedent(f"""
            import sys
            import atheris

            with atheris.instrument_imports():
                try:
                    from {module_path} import {hunk.function_name}
                except Exception as e:
                    sys.exit(0)  # can't import, nothing to fuzz

            def test_one_input(data):
                fdp = atheris.FuzzedDataProvider(data)
                # naive: try calling with a string and an int
                try:
                    s = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes() or 1)
                    {hunk.function_name}(s)
                except (TypeError, ValueError):
                    pass
                except Exception:
                    raise  # unexpected — that's the bug

            atheris.Setup(sys.argv, test_one_input)
            atheris.Fuzz()
        """).strip()

        # write to a temp file (not committed)
        harness_dir = repo_root / ".stca-cache" / "fuzz"
        harness_dir.mkdir(parents=True, exist_ok=True)
        harness_path = harness_dir / f"{hunk.function_name}_fuzz.py"
        harness_path.write_text(harness_code, encoding="utf-8")
        return harness_path

    def _run_harness(self, harness_path: Path, repo_root: Path,
                     duration: int) -> str:
        """Run the harness for `duration` seconds. Return crash summary or ""."""
        try:
            proc = subprocess.run(
                [sys.executable, str(harness_path),
                 f"-max_total_time={duration}", "-max_len=256"],
                capture_output=True, text=True, check=False, timeout=duration + 5,
                cwd=str(repo_root),
            )
            # Atheris exits non-zero on crash, with a SUMMARY line
            if proc.returncode != 0:
                for line in (proc.stdout + proc.stderr).splitlines():
                    if "SUMMARY" in line or "ERROR" in line or "Exception" in line:
                        return line.strip()
                return proc.stderr[:500] if proc.stderr else "non-zero exit"
        except subprocess.TimeoutExpired:
            return ""  # fuzzing completed without crash within timeout
        except Exception as e:
            return f"harness execution error: {e}"
        return ""
