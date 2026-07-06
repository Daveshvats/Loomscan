# Worklog — stca-pipeline P0/P1 follow-up fixes

---
Task ID: 1
Agent: main
Task: Continue P0/P1 fixes from v3.0 audit — survey remaining issues

Work Log:
- Inspected repository state; v3.0 commit (e6d14a8) already in place
- Ran full test suite: 213 passed, 2 failed
  - test_nullness_detects_none_dereference
  - test_nullness_detects_subscript_on_none
- Both failures stem from `_collect_none_sources` in nullness.py only treating
  attribute calls (obj.get()) as None-returning, NOT bare function calls
  (get_value()). Tests expect bare function calls to be treated as possibly-None.
- Scanned orchestrator.py for remaining `except Exception: pass` patterns:
  found ~12 silent error swallowing sites in scanner methods (lines 639-900+)
  that were NOT covered by the v3.0 fix (which only targeted _run_v2_analyzers)

Stage Summary:
- Remaining P0/P1 work identified:
  1. nullness.py: extend None-source detection to bare function calls
  2. orchestrator.py: replace remaining `except: pass` with logged warnings
- Will proceed to fix both, then re-run full test suite

---
Task ID: 2
Agent: main
Task: Fix nullness analyzer — bare function calls not treated as possibly-None

Work Log:
- Inspected failing tests: test_nullness_detects_none_dereference and
  test_nullness_detects_subscript_on_none
- Root cause: `_collect_none_sources` only flagged `ast.Attribute` calls
  (obj.get()) as None-returning, not bare `ast.Name` calls (get_value())
- Added bare function call handling with NON_NONE_BUILTINS allowlist to
  suppress obvious non-None cases (len, str, list, etc.)
- Also fixed `_reassigned_to_non_none_before` which was incorrectly treating
  ALL bare function calls as non-None reassignments, contradicting the new
  source detection logic
- Updated module docstring to reflect new behavior

Stage Summary:
- All 5 nullness tests now pass
- Full test suite: 215 passed, 0 failed
- NON_NONE_BUILTINS allowlist excludes 25+ guaranteed non-None builtins
  to keep false positives down

---
Task ID: 3
Agent: main
Task: Fix silent error swallowing in orchestrator scanner methods

Work Log:
- Surveyed orchestrator.py: found 17 silent `except Exception: pass` patterns
  in scanner methods (v3.0 only fixed _run_v2_analyzers)
- Added module-level `import logging` and `logger = logging.getLogger("stca")`
- Added `_log_scanner_error(name, e, exc_info=False)` helper for consistent
  error reporting
- Replaced all 17 silent patterns with logged warnings via regex script
  (scripts/fix_silent_except.py)
- Each scanner now logs its name + error message; issue_store.upsert failures
  include exc_info=True for full traceback

Stage Summary:
- 0 silent `except: pass` patterns remain in orchestrator.py
- 18 `_log_scanner_error` call sites (17 scanners + 1 helper definition)
- End-to-end scan now reveals 4 previously-silent bugs:
  * scan_malicious_patterns not imported (missing import)
  * scan_pii not imported (missing import)
  * PII scanner: `Path.glob()[:10]` fails (generator not subscriptable)
  * CounterfactualMutator API mismatch (constructor + verify_finding signature
    + MutationResult attribute names all wrong)

---
Task ID: 4-6
Agent: main
Task: Fix surfaced bugs and verify end-to-end behavior

Work Log:
- Fixed missing import: `from .malicious_patterns import scan_repo_malicious_patterns, scan_malicious_patterns`
- Fixed missing import: `from .pii_detection import scan_repo_pii, scan_pii`
- Fixed PII scanner: wrapped `self.repo_root.glob(pattern)` in `list(...)` before slicing
- Fixed CounterfactualMutator usage:
  * Construct with `detector=...` kwarg (was calling with no args)
  * Call `verify_finding(file_path, line, rule_id)` (was calling with wrong signature)
  * Use `result_mut.detector_still_fires` and `result_mut.strategy` (was using
    non-existent `finding_disappeared` and `mutation_strategy` attributes)
  * Construct fresh mutator per finding (detector is rule-specific)

Stage Summary:
- End-to-end scan on sample-python-repo: 49 findings, BLOCK (was 47 with errors)
- End-to-end scan on multi-lang-vuln: 293 findings, BLOCK (no errors)
- End-to-end scan on vuln-app: 238 findings, BLOCK (no errors)
- All 215 tests pass
- All scanner errors now visible in logs — no more silent failures

---
Task ID: 8
Agent: main
Task: Extend silent-except audit to all stca modules

Work Log:
- Surveyed all 64 .py files under stca/ for silent `except Exception: pass`
  patterns: found 45 sites across 25 files
- Categorized each site by role:
  * File I/O / JSON parsing / scanner calls → log at WARNING level
    (failures lose data — user should know)
  * Optional language parsers / external tool invocation / per-file
    iteration → log at DEBUG level
    (failures are common and acceptable; avoids log spam)
- Wrote scripts/fix_silent_except_v2.py to apply replacements atomically.
  Each replacement anchored on unique surrounding context for safety.
- Added module-level `logger = logging.getLogger("stca.<module>")` to
  all 25 affected files (none had loggers before).
- Caught and fixed an insertion bug: my docstring-detection logic
  mishandled single-line module docstrings (both `"""` on line 1),
  causing the logger to be inserted INSIDE a function docstring in
  cli.py. Fixed manually and wrote find_bad_loggers.py AST-based
  verifier to catch any similar issues — 0 problematic files remain.

Files modified (25):
- baseline.py, brain/aggregator.py, brain/project_tuner.py
- cli.py (3 SBOM parsing sites: package.json, go.mod, Cargo.lock)
- deadcode.py, diff_slicer.py (6 tree-sitter parser sites)
- feedback/stats.py, hotspots.py, incremental.py, installer.py
- interprocedural.py (2 per-file iteration sites)
- js_cpg.py, layers/l0_fast.py
- layers/l0b_supply_chain.py (5 audit functions)
- layers/l0c_dependencies.py (4 dep-check functions)
- layers/l7_simulation.py, layers/l8_autofix.py (3 sites)
- learning.py, multi_lang.py, precision.py (2 sites)
- profiles.py, report/dashboard.py, rule_config.py
- rules/__init__.py, unified_cve_db.py (2 sites)

Deliberate exceptions (documented in commit message):
- learning.py load() — has intentional `self.vectors = {}` fallback
- deadcode.py:187 — code template injected into user code (no logger access)

Stage Summary:
- 44/45 silent patterns replaced (1 is a code template, left as-is)
- 0 silent `except: pass` patterns remain in the stca package
- 25 module-level loggers added
- All 215 tests pass
- End-to-end scans: vuln-app, multi-lang-vuln, sample-python-repo all run cleanly
- CLI commands (--help, --version, check, sbom) all working
- Helper scripts persisted to scripts/:
  * survey_silent_except.py — count silent patterns per file
  * show_silent_context.py — display context for manual review
  * fix_silent_except_v2.py — apply replacements atomically
  * find_bad_loggers.py — AST-based verifier for logger placement

---
Task ID: 9
Agent: main
Task: v3.1 — surface previously-silent scanner failures in reports

Work Log:
- Identified the "last mile" problem: we added logging to 44+ silent
  except sites, but logs scroll by and aren't visible in the final
  deliverable (TUI/JSON/SARIF reports)
- Designed scanner health tracking system:
  * PipelineResult.scanner_health: List[Dict] field
  * Orchestrator._scanner_health: per-run list, reset each run
  * _scanner_error() method: logs AND tracks in health list
  * All 17 scanner call sites rewired to use the new method
- Surfaced scanner_health in 3 report formats:
  * TUI: yellow banner at top + Scanner Health table at bottom
  * JSON: scanner_health + scanner_error_count in to_dict()
  * SARIF: executionSuccessful=False + toolExecutionNotifications
    (compatible with GitHub Code Scanning + VS Code SARIF Viewer)
- Added 2 CLI flags:
  * --strict-scanners: exit code 3 if any scanner failed (CI gate)
  * -v/--verbose: enable DEBUG-level logging on stca namespace
- Wrote 12 new tests covering all the above (tests/test_scanner_health.py)

Stage Summary:
- 227/227 tests passing (215 original + 12 new)
- Scanner failures now visible in:
  * Logs (WARNING level) — always
  * TUI banner + table — always (when failures occur)
  * JSON report — always
  * SARIF report — always (toolExecutionNotifications)
  * CI exit code — opt-in via --strict-scanners
  * DEBUG diagnostics — opt-in via --verbose
- 0 silent failure paths remain in the scanner pipeline
