# Changelog

All notable changes to LoomScan are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [7.6.0] — 2026-07-17

### Architecture
- **cli.py split into cli/ package** — the 3,678-line monolithic `cli.py` is now a
  package with 3 files:
  - `cli/__init__.py` (3,154 lines) — main Click group + all legacy commands
  - `cli/advanced.py` (358 lines) — v7.4-v7.5 commands: learn, second-opinion, diff,
    gnn-score, gnn-train
  - `cli/security.py` (204 lines) — v7.5 restored-module commands: jsx-auth,
    stateful-pbt, multi-call
  - All 58 commands still registered. Backward-compatible re-exports in `__init__.py`.
- **v4_restored.py fully retired from orchestrator** — orchestrator no longer
  imports from `v4_restored.py` (uses `v4_aggregator.py` instead).
- **GUIDE.md fully refreshed** — from v4.43 to v7.6.0 with all new features documented.

### Fixed
- Pack rule count drift test now allows growth (declared count is a floor, not exact)
- 3 test files updated to read `cli/__init__.py` instead of deleted `cli.py`
- `test_guide_has_updated_toc` accepts "Strictness" as alternative to "Quality Gates"

### Test Results
- **361 tests pass, 0 fail** (116 more tests collected than v7.5.6)
- All 6 CI-referenced scripts pass
- Python 20/20 E2E detection preserved

## [7.5.5] — 2026-07-17

### Fixed
- **P1: Missing `Path` import in `test_v734_explainable_aggregator.py`** — the
  v7.5.4 `fix_hardcoded_paths.py` script replaced the hardcoded path with
  `str(Path(__file__).resolve().parent.parent)` but forgot to add
  `from pathlib import Path`. This was 1 of 6 CI-referenced scripts and would
  have failed on GitHub Actions with `NameError: name 'Path' is not defined`.
  Added the missing import. Verified: all other scripts already had the import.
- **P2: 3 remaining stale test failures fixed** (now **zero failures**):
  - `test_v58_smoke::test_readme_mentions_spider_and_3tier` — spider mascot
    was removed in v5.17; now accepts spider emoji 🕷️ + `[all]` as alternative
    to `[fast]` (which was removed from README as it's just an alias for `[full]`)
  - `test_v58_smoke::test_pyproject_core_deps_are_pure_python` — numpy was
    intentionally removed in v7.2.1 (never imported); removed from required deps
  - `test_v57_smoke::test_readme_mentions_tui_and_mascot` — "Loomy" mascot name
    was removed when TUI was replaced with Rich CLI (v5.17); now accepts "Rich
    CLI" as alternative

### Test Results
- **278 tests pass, 0 fail** (was 278 pass / 3 fail in v7.5.4)
- All 6 CI-referenced scripts pass
- All v7.3.x regression scripts pass
- Python 20/20 E2E detection preserved

## [7.5.4] — 2026-07-17

### Security
- **P0: installer SHA256 verification — ALL binary tools now verified** (was 7
  releases overdue). All 7 binary ToolSpecs now have `checksum_url` set:
  gitleaks, semgrep, osv-scanner, opa, trivy, kics, trufflehog. At install
  time, the release's published `checksums.txt` is downloaded, parsed, and the
  binary's SHA256 is verified against it. If verification fails, install is
  refused. Override with `LOOMSCAN_ALLOW_UNVERIFIED_INSTALL=1` (NOT RECOMMENDED).

### Fixed
- **P1: 19 hardcoded `/home/z/my-project` paths fixed across 16 files**. The
  v7.5.3 CHANGELOG claimed this was fixed in `test_v751_smoke.py:18` (which it
  was), but the IDENTICAL bug existed in 12 other scripts/tests files. All 6
  CI-referenced scripts (`test_v731_rules.py` through `test_v734_explainable_aggregator.py`)
  would have failed on GitHub Actions runners with `FileNotFoundError`. Fixed
  via `scripts/fix_hardcoded_paths.py` — all paths now use
  `Path(__file__).resolve().parent.parent` or pre-computed `_project_root`.
- **Subprocess test fixes**: `test_v59_smoke.py`, `test_v511_smoke.py`,
  `test_v58_smoke.py` had `Path` references inside `python -c` string literals
  where `Path` wasn't imported. Fixed by computing `_project_root` BEFORE the
  subprocess call and injecting it via f-string.

## [7.5.3] — 2026-07-17

### Fixed
- **P1: NODE_FEATURE_DIM bug** — `gnn_cpg.py:79` said `NUM_NODE_TYPES + 5` (= 21)
  but `build_cpg()` computed 6 numeric features (16 one-hot + 6 = 22). The
  `depth / 10.0` feature was silently truncated by `features[:NODE_FEATURE_DIM]`.
  Fixed: `NODE_FEATURE_DIM = NUM_NODE_TYPES + 6` (= 22). Added `assert
  len(features) == NODE_FEATURE_DIM` to catch future regressions.
- **P1: 5 stale tests fixed**:
  - `test_v443_smoke::test_readme_mentions_2254_rules` → `test_readme_mentions_rule_count`
    (dynamic regex, accepts any count >= 1000)
  - `test_v5_smoke::test_readme_says_v5` → `test_readme_mentions_current_version`
    (dynamic, accepts any v5+ version)
  - `test_v5_smoke::test_workflow_checks_properties_severity` → checks `ci.yml`
    instead of deleted `loomscan.yml`
  - `test_v59_smoke::test_v58_rust_wheel_workflow_exists` → accepts either
    `build-rust-wheels.yml` or `ci.yml`
- **P1: Duplicate rule IDs fixed**:
  - `leak-threadlocal-no-remove` (duplicated within `java-production-incidents.yml`)
    → renamed older occurrence to `leak-threadlocal-static-field`
  - `java-resttemplate-no-timeout` (duplicated across `java-deep.yml` and
    `java-production-incidents.yml`) → renamed `java-deep.yml` version to
    `java-resttemplate-no-timeout-deep`
- **P2: Hardcoded path in test** — `tests/test_v751_smoke.py:18` had
  `sys.path.insert(0, "/home/z/my-project")` (auditor's local path). Replaced
  with `str(Path(__file__).resolve().parent.parent)` — works on any machine/CI.

## [7.5.2] — 2026-07-17

### Fixed
- **P0-4: jsx-auth CLI attribute error** — `cli.py:3395` referenced
  `rule.pattern_type` (doesn't exist). Fixed to `rule.wrapper_kind` +
  `rule.pattern_text`.
- **P1-5: gnn-score feedback-loop** — `scan_repo_with_gnn()` had its own
  inline skip set that didn't include `.loomscan-cache`. Replaced with
  `from ._paths import is_skipped_dir`.

### Added
- **GNN multi-language support** — `score_file_with_gnn()` now works across
  7 languages (Python, Java, JavaScript, TypeScript, Go, C/C++, Rust) via
  regex-based function extraction + simplified CPG for non-Python languages.
- **`[full]` extra now includes semgrep + GNN deps** — `pip install
  loomscan[full]` now installs `semgrep>=1.50` + `torch>=2.0` +
  `torch-geometric>=2.4` alongside tree-sitter, Rust core, and TUI.

## [7.5.1] — 2026-07-17

### Fixed
- **P0-1: gnn_cpg.py NameError when torch not installed** — `class
  GNNOnCPGModel(nn.Module)` was defined unconditionally at module top-level.
  When torch was absent (default install), `nn` was undefined → NameError →
  entire pytest suite failed to collect. Fixed: added stub
  `nn = type("nn", (), {"Module": object})()` in the except branch.
- **P0-2: jsx-auth CLI calls non-existent `.detect()`** —
  `JSXAuthViolationDetector` only has `.analyze()`. Fixed method call.
- **P1-3: multi_call feedback-loop** — `multi_call.py` had no `skip_dirs`
  handling, scanned `.loomscan-cache/` files. Added `scan_repo_multi_call()`
  using `is_skipped_dir` from `_paths.py`.

### Added
- **Restored modules wired into orchestrator** — `multi_call`, `jsx_auth`,
  `stateful_pbt` now fire automatically in `loomscan check --full` when the
  repo contains matching file types.
- **13 smoke tests** in `tests/test_v751_smoke.py` — invoke each new CLI
  command to catch runtime errors.

## [7.5.0] — 2026-07-17

### Real GNN-on-CPG (not the coward's path)
- **NEW: `loomscan/gnn_cpg.py`** — Real Graph Neural Network with LEARNED weights,
  not the v7.3.4 HeuristicRiskScorer (hand-tuned logistic regression). Built with
  torch-geometric's `GCNConv` layers:
  - **Code Property Graph builder**: AST nodes + AST edges + data-flow edges
    (def→use) + call edges (Call→FunctionDef). 16-dim node type one-hot + 5
    numeric features (calls, branches, loops, sensitive tokens, unsafe libs).
  - **GNN model**: `GCNConv(21, 64) → ReLU → Dropout(0.1) → GCNConv(64, 32) → ReLU
    → global_mean_pool → Linear(32, 16) → ReLU → Linear(16, 1) → Sigmoid`
  - **Training**: binary cross-entropy on labeled findings (TP=1.0, FP=0.0).
    Model saved to `~/.loomscan-cache/gnn_model.pt`.
  - **Fallback**: if torch/torch-geometric not installed, falls back to
    HeuristicRiskScorer with a warning.
- **New CLI commands**:
  - `loomscan gnn-score --repo . [--threshold T]` — score functions with real GNN
  - `loomscan gnn-train --label-db PATH [--epochs N] [--lr LR]` — train on labels
- **16 GNN tests** in `tests/test_gnn_cpg.py` — CPG builder, model forward pass,
  learned-weights verification, function scoring, training, repo scanning.

### Restored modules (v7.4.0 deletion was a strategic mistake)
- **`loomscan/jsx_auth.py`** (219 LOC) — RESTORED from git history. JSX/React
  authorization coverage analysis. Detects HOC patterns, hook patterns, route
  guards. Flags pages WITHOUT auth wrappers. Wired via `loomscan jsx-auth --repo X`.
- **`loomscan/stateful_pbt.py`** (262 LOC) — RESTORED. Stateful property-based
  testing inspired by Echidna + Hypothesis RuleBasedStateMachine. Catches
  multi-step state bugs static analysis cannot. Wired via
  `loomscan stateful-pbt --repo X [--target CLASS]`.
- **`loomscan/multi_call.py`** (322 LOC) — RESTORED. Cross-function call-chain
  analysis: reentrancy, missing-auth-in-chain, TOCTOU. Wired via
  `loomscan multi-call --repo X [--check all|reentrancy|missing-auth|toctou]`.
- **`test_frontier_techniques.py`** — restored imports (no longer skips).

### Release engineering fixes
- **P0 fix**: tarball now includes `tests/` and `scripts/` directories. Previous
  v7.4.0 tarball omitted them, causing CI to fail with "file or directory not found".
- **CI workflow bracket bug**: verified the file bytes are correct (`[main, develop]`
  at byte level). The `ain, develop]` rendering is a terminal false-positive
  (CSI `[m` interpreted as ANSI "reset all attributes" escape). No fix needed —
  auditor was wrong (same terminal-rendering issue as v7.3.1).

### Added
- `loomscan/gnn_cpg.py` — real GNN implementation (torch-geometric).
- `tests/test_gnn_cpg.py` — 16 GNN tests.
- 5 new CLI commands: `jsx-auth`, `stateful-pbt`, `multi-call`, `gnn-score`, `gnn-train`.

## [7.4.0] — 2026-07-17

### Architecture
- **v4_restored.py deprecated**: Marked with `DeprecationWarning` on import.
  The orchestrator now suppresses the warning during the transition period.
  Will be removed in v8.0 — new code should import directly from the
  underlying modules (`expanded_rules`, `codebase_understanding`, etc.).
- **3 dead modules deleted**: `jsx_auth.py` (219 LOC), `stateful_pbt.py`
  (262 LOC), `multi_call.py` (322 LOC) — 803 LOC removed. These modules
  were never imported by any production code; only test code referenced
  them. `test_frontier_techniques.py` updated to skip the deleted-module
  tests via `pytest.importorskip`.

### Wired (previously-dead classes now reachable)
- **`ActiveLearning`** (learning.py:107): Now wired via `loomscan learn`
  CLI command. Suggests which findings a human should label next based on
  uncertainty, novelty, and disagreement signals.
- **`ExplainableAggregator`** (brain/bayesian.py:294): Now wired via
  `loomscan second-opinion` CLI command. Combines FIS + BBN + counterfactual
  into an explainable decision with reasoning trace.
- **`DifferentialAnalyzer`** (incremental.py:190): Now wired via
  `loomscan diff --baseline <file>` CLI command. Compares current scan
  against a baseline JSON, reports added/removed findings.

### Added
- **CONTRIBUTING.md**: Comprehensive contributor guide — setup, testing,
  code style, rule pack authoring, detection engine architecture, release
  process.
- **GitHub Actions CI** (`.github/workflows/ci.yml`): 4-job pipeline —
  `test` (Python 3.12/3.13 on Ubuntu/macOS), `lint` (ruff + black + mypy),
  `rule-validation` (all YAML packs load + all regex patterns compile),
  `build` (python -m build + twine check).
- **`tests/test_brain.py`**: 21 unit tests for `loomscan.brain` package —
  membership functions (IT2 triangular/trapezoidal), BBNEvidence,
  BayesianSecondOpinion, ExplainableAggregator (incl. counterfactual
  FP downgrade + TP confirmation + trace), IT2FIS, Decision enum.
- **Decorator-based fix registry** (`l8_autofix.py`): New `@fix_for()`
  decorator + `get_all_fix_patterns()` + `find_fix_for_rule()` accessors.
  Existing `FIX_PATTERNS` list preserved for backward compat; new fixers
  should use the decorator.

### CLI
- New command: `loomscan learn [--top-k N] [--label-db PATH]` — active
  learning suggestions.
- New command: `loomscan second-opinion [--threshold T]` — Bayesian second
  opinion on findings.
- New command: `loomscan diff --baseline <file> [--current <file>]` —
  differential analysis vs baseline.

## [7.3.4] — 2026-07-17

### Security
- **P0 fix**: `loomscan install-tools` now **REFUSES** to install binary
  tools without a pinned SHA256 checksum. Previously, missing checksums
  only produced a warning and the install proceeded anyway — a supply-chain
  security bug. Override with `LOOMSCAN_ALLOW_UNVERIFIED_INSTALL=1` (NOT
  RECOMMENDED).
- Added `sha256_file()` helper for diagnostic output on verification failure.
- Added `SECURITY.md` with vulnerability disclosure policy, threat model,
  and supply-chain security documentation.

### Fixed
- **P0 fix**: `bl.db.write_in_loop` suppression scope corrected. The v7.3.3
  implementation used a ±1500 char context window that spanned multiple
  Java methods — if any method in the file used `saveAll()`, ALL
  `write_in_loop` findings in the file were suppressed. Now scoped to the
  matched loop body only.
- **P1 fix**: `warn_on` config field is no longer dead. Added
  `StrictnessLevel.warn_on` field and `should_warn()` function in
  `strictness.py` to mirror `should_block()`. Users who set
  `warn_on: [...]` in `.loomscan.yaml` now get the expected non-blocking
  warning behavior.

### Changed
- **P1 fix**: `GNNOnCPG` class renamed to `HeuristicRiskScorer` to honestly
  reflect the implementation (hand-tuned linear-feature logistic regression
  over regex-extracted features — no graph, no neural network, no learned
  weights, no CPG). Backward-compat alias `GNNOnCPG = HeuristicRiskScorer`
  preserved for external imports; will be removed in v8.0.
- Updated `learning.py` module docstring to match the rename.
- Updated `scan_repo_with_gnn()` to use `HeuristicRiskScorer` internally
  (function name kept for backward compat).

### Documentation
- Added `CHANGELOG.md` (this file).
- Added `SECURITY.md` with disclosure policy and threat model.

## [7.3.3] — 2026-07-16

### Fixed
- `java-thread-sleep-in-request` regex broadened from `Thread\.sleep\s*\(\s*\d+\s*\)`
  to `Thread\.sleep\s*\(` — now catches `Thread.sleep(50_000)` (underscore
  separator), `Thread.sleep(timeout)` (variable), and
  `Thread.sleep(TimeUnit.SECONDS.toMillis(5))` (computed).
- Added `bl.db.write_in_loop` BL-miner pattern to cover the multi-line
  `for (...) { ...; repo.save(x); }` case that the YAML rule
  `jpa-saveall-in-loop` misses (YAML engine scans line-by-line).
- `llm-api-key-hardcoded` now matches SDK form (`openai.api_key = "sk-..."`
  in addition to env-var form `OPENAI_API_KEY=...`).
- `llm-temperature-too-high` now uses `[=:]` to match both Python kwarg
  form (`temperature=1.5`) and JSON/dict form (`temperature: 1.5`).
- README: marked Integer Overflow as ✅ (detector shipped in v7.2). Updated
  detection rate from "19/20 (95%)" to "20/20 (100%)".

## [7.3.2] — 2026-07-16

### Security
- **P0 fix**: `java-production-incidents` pack (308 rules) and `ai-security`
  pack (12 rules) were registered in `BUILTIN_PACKS` but never loaded by
  `get_all_packs_for_files()`. All v7.3 features were dead code in
  `loomscan check --full`. Now wired in `loomscan/rules/__init__.py`.

### Fixed
- **P1 fix**: 3 multi-line regex rules rewritten to single-line patterns
  (`err-throw-in-finally`, `jpa-saveall-in-loop`, `err-catch-return-swallow`).
  The YAML engine scans line-by-line, so multi-line patterns never matched.
- **P2 fix**: HTML report version stamp now uses `loomscan.__version__`
  instead of hardcoded `"5.22.0"`.
- **P2 fix**: HTML report findings capped at 5000 (sorted by severity) to
  prevent 150MB+ dashboards. Truncation indicator added.
- **P2 fix**: `html_scanner.py` input file size capped (10MB HTML, 5MB
  .env/config) to prevent OOM.
- **P2 fix**: README stats reconciled — all references now say "2,473 rules".
- **P3 fix**: `sgi-docker-no-healthcheck` no longer fires on every line of
  every file. Restricted to Dockerfile instruction keywords.
- **P3 fix**: `py-secrets-good` and `sgpy-secrets-token` disabled — they
  flagged GOOD code as findings.
- **P3 fix**: `py-print-secret`, `py-logger-secret`, `deep-py-print-secret`,
  `py-logging-debug-secret`, `owasp-a09-print-credentials` tightened to
  only flag direct secret arguments (not format strings containing the
  word "token").
- **P3 fix**: `hotspots.py` `eval`/`exec` substrings changed to `eval(`/`exec(`
  to avoid matching `conn.execute()` / `retrieval`.

### Added
- `scripts/test_v732_pack_loading.py` — regression test asserting
  `java-production-incidents` and `ai-security` are loaded.
- `scripts/test_v732_clean_code_fp.py` — clean-code false-positive test.

## [7.3.1] — 2026-07-16

### Added
- 142 new Java production-incident YAML rules (sections 46–63):
  - Memory leaks, thread safety, null safety, exception handling, resource cleanup
  - Spring anti-patterns, validation missing, concurrency, string/collections misuse
  - I/O performance, time/date misuse, logging misuse, HTTP/REST issues
  - Serialization, reflection, class loading, JMX/JNDI, Spring Security misconfig
- 12 new BL-miner Java/Spring cross-line patterns (`_JAVA_RISK_PATTERNS`):
  - parallelStream in request, Collectors.toMap without merge, stream consumed twice,
    Optional chain .get(), swallow+return null, catch-log-rethrow, sync HTTP in request,
    loop-size-grows, stream forEach side-effect, @Transactional private method,
    @Transactional self-invocation, InterruptedException not restored, multiple findById,
    stream count==0, collect-then-foreach.

### Fixed
- `java-enum-valueof-without-validation` simplified — now matches both
  `EnumType.valueOf(var)` AND `Enum.valueOf(Type.class, var)` forms.
- `java-sync-blocking-endpoint-no-timeout` URL keyword list expanded
  (added `generate`, `process`, `batch`, `bulk`, `convert`, `download`,
  `backup`, `restore`, `archive`, `render`, `compile`, `build`, `analyze`,
  `scan`, `aggregate`, `compute`, `calculate`, `crunch`, `etl`, `transform`).
- Added `java-sync-endpoint-with-requestbody-no-async` companion rule.

## [7.3.0] — 2026-07-16

### Added
- **65 DB anti-pattern YAML rules** in `java-production-incidents.yml`
  (sections 31–45): transaction management, query inefficiency, JPA/EntityManager
  misuse, JPA entity design, locking & concurrency, Hibernate-specific,
  connection & datasource, save patterns, cache misuse, schema migration/DDL,
  index & query plan, Spring Data JPA method naming, audit & soft delete,
  migration safety.
- **17 BL-miner DB patterns** (`_DB_RISK_PATTERNS`): load-all-for-count,
  load-entity-for-one-field, N+1-in-loop, read-modify-write-no-lock, etc.
- **Dead-persistence detector** in `codebase_understanding.py`:
  `detect_dead_persistence()` flags entities saved but never read anywhere
  in the codebase. New `FunctionBehavior.entity_types_written` and
  `entity_types_read` fields.
- **2 missing source-detection rules**: `java-enum-valueof-without-validation`
  (catches "No enum constant" 500s), `java-sync-blocking-endpoint-no-timeout`
  (catches 57-second timeouts).
- Fixed `_index_multi_file` to fall back to extension-based language
  detection when tree-sitter isn't installed.

## [7.2.1] — 2026-07-15

### Fixed
- 15 broken regex patterns ( `\A\z`, `**`, bare `[`) fixed to `(?!)` or escaped.
- Regex caching (`_COMPILED_REGEX_CACHE`) added to `yaml_engine.py` — avoids
  3000 recompiles per scan.
- CPG cache (`self._cpg_cache`) added to orchestrator — was building twice
  per scan.
- Functional dedup with `msg_hash` — same finding from multiple packs no
  longer reported twice.
- False-positive suppression — FP-marked findings no longer reappear.
- `baseline create` uses `run_full()` instead of `run()` (diff mode).
- `--uncertain` decisions slicing fixed to match filtered findings.
- Unified skip dirs via `_paths.py` (`DEFAULT_SKIP_DIRS` +
  `is_loomscan_artifact()`) — fixes feedback loop where LoomScan scanned
  its own output.
- Removed `numpy`/`jsonschema` from deps (never imported).

## [7.2.0] — 2026-07-15

### Added
- Integer overflow detector (`integer_overflow_detector.py`) — type inference
  heuristic for Java/Python arithmetic.
- Dynamic CVE checker (`dynamic_cve_checker.py`) — detects deps from lock
  files, queries OSV API, checks reachability.
- IDE docs (VS Code, JetBrains).

## [7.1.0] — 2026-07-14

### Added
- Dynamic CVE checker with OSV API integration.
- Reachability analysis for vulnerable dependencies.

## [7.0.0] — 2026-07-14

### Added
- Integer overflow detection.
- CVE rules pack.
- IDE integration documentation.

## [6.2.x] — 2026-07-13

### Added
- Merge review command (`loomscan merge-review --base main`) with blast
  radius and HTML export.
- CVE database for enrichment (16 CWEs → 40+ known CVEs).
- AI/LLM security pack (12 rules).

## [6.0.0] — 2026-07-12

### Added
- TOCTOU detector (AST-based race condition detection).
- Business logic miner (domain-aware: quantity, price, money, discount, tax).
- Field taint tracker (IDOR, mass assignment, privilege escalation).
- Deep dataflow (JS/Java source→sink taint tracking).

## [5.x] — 2026-07-10 to 2026-07-11

### Added
- Rich CLI display with two-column live layout.
- Engine selection (`--engine auto/rust/semgrep/python/all`).
- Exclude system (`--exclude` + `.loomscanignore`).
- Java production-incident rules pack (101 rules).
- HTML report redesign (dark Hermes-inspired theme).
- Runtime error scanner (`.log` file analysis).
- Multi-engine consolidation with dedup.
- 3-tier install model (basic/full/all).
- `loomscan doctor` command.
- `.loomscanignore` auto-generation.
