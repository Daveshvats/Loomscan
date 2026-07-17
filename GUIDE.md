# LoomScan — Complete User Guide

> **v7.5.6** — Static + Test + Constraint Analysis. A deterministic-first, type-2 fuzzy aggregated bug detection pipeline that runs on any laptop, offline, across **24 programming languages** with **2,473 rules**, **308 Java production-incident rules**, **real GNN-on-CPG with learned weights**, and **76+ detection engines**.

This guide covers everything: installation, configuration, daily usage, CI/CD integration, advanced features, troubleshooting, and internals. Read it top-to-bottom for a full understanding, or jump to the section you need using the table of contents.

---

## Table of Contents

1. [What LoomScan Does](#1-what-loomscan-does)
2. [Installation](#2-installation)
3. [Quick Start (5 Minutes)](#3-quick-start-5-minutes)
4. [Core Commands](#4-core-commands)
5. [Strictness Levels (1-9)]#5-strictness-levels-1-9)
6. [Reports and Dashboards](#6-reports-and-dashboards)
7. [Configuration (.loomscan.yaml)](#7-configuration)
8. [Auto-Fix (107 patterns)](#8-auto-fix)
9. [IDE Integration](#9-ide-integration)
10. [CI/CD Integration](#10-cicd-integration)
11. [Unique Features](#11-unique-features)
12. [Rule Management](#12-rule-management)
13. [GNN-on-CPG](#13-gnn-on-cpg)
14. [Restored Modules](#14-restored-modules)
15. [Troubleshooting](#15-troubleshooting)
16. [Internals](#16-internals)

---

## 1. What LoomScan Does

LoomScan is a **multi-language static + dynamic + symbolic code analysis pipeline**. It detects bugs, security vulnerabilities, performance issues, and production-incident patterns **before code reaches production**.

### Key Differentiators (no competitor has all of these)

| Feature | Description |
|---------|-------------|
| **Real GNN-on-CPG** | 2-layer GCN with learned weights (torch-geometric) operating on Code Property Graphs. Trains on labeled findings. Multi-language (Python, Java, JS/TS, Go, C/C++, Rust). |
| **Database anti-pattern detection** | 308 Java production-incident rules — transaction management, N+1 queries, missing `readOnly`, dead persistence, EAGER fetch, and more. No competitor catches these. |
| **Business logic miner** | Domain-aware patterns (quantity×price without validation, missing balance check, read-modify-write without locking). |
| **Stateful PBT** | Stateful property-based testing (Echidna-inspired). Catches multi-step state bugs static analysis cannot. |
| **Multi-call analysis** | Cross-function call-chain analysis (reentrancy, missing-auth-in-chain, TOCTOU). |
| **JSX auth coverage** | React/Next.js authorization coverage analysis. Flags pages without auth wrappers. |
| **Merge review** | Pre-merge branch analysis with blast radius and recommendation. |
| **Dead persistence detection** | Finds entities saved to DB but never read anywhere in the codebase. |
| **Dynamic CVE checker** | Detects deps from lock files, queries OSV API, checks reachability. |
| **Runtime error scanner** | Scans .log files for Java OOM, UUID errors, 500s, NPEs. |
| **IT2-FIS aggregation** | Interval type-2 fuzzy inference system for finding aggregation. |
| **Bayesian second opinion** | ExplainableAggregator combines FIS + BBN + counterfactual. |

### Detection Coverage: 20/20 (100%)

| # | Vulnerability | Engine |
|---|--------------|--------|
| 1 | SQL Injection | YAML + taint + OWASP |
| 2 | Command Injection | YAML + code_quality |
| 3 | Hardcoded Secret | Regex + entropy |
| 4 | Missing Auth | Auth detector + BL |
| 5 | Race Condition (TOCTOU) | TOCTOU detector (AST) |
| 6 | Integer Overflow | Integer overflow detector (v7.2) |
| 7 | Business Logic (neg qty) | Domain-aware BL miner |
| 8 | Missing Transaction | Typestate protocol |
| 9 | Log Injection | Code quality + CPG |
| 10 | Insecure Random | YAML + crypto |
| 11 | XSS | YAML + taint |
| 12 | Path Traversal | YAML + taint |
| 13 | SSRF | YAML + taint |
| 14 | Deserialization | YAML + taint |
| 15 | XXE | YAML |
| 16 | ReDoS | YAML (nested quantifiers) |
| 17 | Open Redirect | YAML + taint |
| 18 | CSRF | YAML + framework |
| 19 | CORS Misconfig | YAML + framework |
| 20 | Mass Assignment | YAML + field_taint |

---

## 2. Installation

### Tier 1: Basic (pure Python, works everywhere)

```bash
pip install loomscan
```

Gets you: all 2,473 rules, Rich CLI display, 76+ engines, HTML/SARIF/JSON reports.

### Tier 2: Full (recommended — includes semgrep + GNN)

```bash
pip install loomscan[full]
```

Adds: tree-sitter (CPG/def-use), Rust core (10-50× faster), TUI, pillow, **semgrep** (all 2,473 rules fire — without it ~914 advanced rules are silently skipped), **GNN-on-CPG** (real torch-geometric model with learned weights, multi-language).

### Tier 3: All (everything including mutation testing, LLM, fuzz)

```bash
pip install loomscan[all]
```

Adds: mutation testing (mutmut), LLM verify (Ollama), fuzz (atheris), premium image rendering.

### Verify Installation

```bash
loomscan --version    # Should show v7.5.6
loomscan doctor       # Check system health
```

---

## 3. Quick Start (5 Minutes)

```bash
# Scan your code (full repo)
loomscan check --full

# Scan only changed files (git diff mode)
loomscan check

# Pre-merge analysis
loomscan merge-review --base main

# GNN risk scoring
loomscan gnn-score --repo .

# Active learning suggestions
loomscan learn --repo .
```

---

## 4. Core Commands

| Command | Description |
|---------|-------------|
| `loomscan check` | Scan changed files (git diff mode) |
| `loomscan check --full` | Scan entire repo |
| `loomscan doctor` | Check system health and tool availability |
| `loomscan merge-review --base main` | Pre-merge analysis with blast radius |
| `loomscan learn --repo .` | Active learning — which findings to label next |
| `loomscan second-opinion --repo .` | Bayesian second opinion on findings |
| `loomscan diff --baseline baseline.json` | Differential analysis vs baseline |
| `loomscan gnn-score --repo .` | GNN risk scoring (real torch-geometric model) |
| `loomscan gnn-train --label-db labels.json` | Train GNN on labeled findings |
| `loomscan jsx-auth --repo .` | JSX/React authorization coverage analysis |
| `loomscan stateful-pbt --repo .` | Stateful property-based testing |
| `loomscan multi-call --repo .` | Multi-call bug detection (reentrancy, TOCTOU) |
| `loomscan install-tools` | Install external tools (semgrep, gitleaks, etc.) |
| `loomscan rules list` | List all rule packs and rule counts |
| `loomscan baseline create` | Create a findings baseline |
| `loomscan feedback tp/fp <rule_id>` | Label findings for GNN training |

---

## 5. Strictness Levels (1-9)

| Level | Name | What Blocks |
|-------|------|-------------|
| 1 | Critical Only | Only CRITICAL findings block |
| 2-3 | High+ | CRITICAL + HIGH block |
| 4-6 | Medium+ | CRITICAL + HIGH + MEDIUM block |
| 7 | Standard (default) | Same as 6, with advanced detection |
| 8 | Strict | Same as 7, with LOW findings |
| 9 | Paranoid | Everything blocks, including WARN |

```bash
loomscan check --full --strictness 9
```

---

## 6. Reports and Dashboards

### HTML Report (interactive dashboard)

```bash
loomscan check --full --html
```

Features: dark Hermes-inspired theme, donut chart, filterable table, code graph, scan config display. Findings capped at 5000 (sorted by severity) to prevent oversized dashboards.

### JSON Report

```bash
loomscan check --full --json > results.json
```

### SARIF Report (for GitHub Code Scanning)

```bash
loomscan check --full --sarif > results.sarif
```

---

## 7. Configuration (.loomscan.yaml)

```yaml
# .loomscan.yaml
strictness: 7
block_on: ["block"]
warn_on: ["warn"]  # v7.3.4: now enforced via should_warn()

exclude:
  - "tests/**"
  - "vendor/**"

engine: auto  # auto | rust | semgrep | python | all
```

---

## 8. Auto-Fix (107 patterns)

```bash
# Show fixes without applying
loomscan check --full --fix

# Apply fixes
loomscan check --full --fix --apply
```

v7.4: New `@fix_for()` decorator-based registry for adding fixers.

---

## 9. IDE Integration

### VS Code

```bash
loomscan lsp  # Start LSP server
```

Add to `.vscode/settings.json`:
```json
{
  "loomscan.enable": true,
  "loomscan.strictness": 7
}
```

### JetBrains

Use the LSP plugin to connect to `loomscan lsp`.

---

## 10. CI/CD Integration

### GitHub Actions

```yaml
- name: LoomScan
  run: |
    pip install loomscan[full]
    loomscan check --full --sarif > results.sarif
    # Upload to GitHub Code Scanning
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
- repo: local
  hooks:
    - id: loomscan
      name: LoomScan
      entry: loomscan check
      language: system
      pass_filenames: false
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No blocking findings |
| 1 | Blocking findings detected |
| 2 | Scanner error |

---

## 11. Unique Features

### GNN-on-CPG (v7.5+)

Real Graph Neural Network with learned weights. Not a heuristic — actual `torch_geometric.nn.GCNConv` layers.

**Architecture**: GCNConv(22, 64) → ReLU → Dropout → GCNConv(64, 32) → ReLU → global_mean_pool → Linear(32, 16) → ReLU → Linear(16, 1) → Sigmoid

**Multi-language**: Python (full AST CPG), Java/JS/TS/Go/C/C++/Rust (regex-based CPG with same feature space).

**Training**: Binary cross-entropy on labeled findings. Model saved to `~/.loomscan-cache/gnn_model.pt`.

```bash
# Score functions
loomscan gnn-score --repo . --threshold 0.5

# Train on your labeled findings
loomscan gnn-train --label-db .loomscan-cache/labels.json --epochs 50
```

### Database Anti-Patterns (v7.3+)

308 Java production-incident rules across 15 categories:
- Transaction management (missing readOnly, rollbackFor, timeout)
- Query inefficiency (findAll().size(), SELECT *, N+1)
- JPA/EntityManager misuse (merge on new entity, manual flush)
- JPA entity design (@OneToMany without mappedBy, @Lob without LAZY)
- Locking & concurrency (PESSIMISTIC_WRITE without timeout)
- Hibernate-specific (deprecated Criteria.list, Query.iterate)
- Save patterns (save() in loop, saveAndFlush, DELETE without WHERE)
- Cache misuse (@Cacheable without @CacheEvict)
- Schema migration (ddl-auto=update, show-sql=true)
- Index & query plan (LIKE '%...', NOT IN, DISTINCT with JOIN)
- Spring Data naming (Containing, IgnoreCase, OrderBy)
- Audit & soft delete (@Where, missing @EntityListeners)
- Migration safety (Flyway baseline-on-migrate, Liquibase dropAll)

### Business Logic Miner (v6.0+)

Domain-aware patterns that need cross-line context:
- `bl.db.load_all_for_count` — findAll().size() instead of count()
- `bl.db.n_plus_1_in_loop` — DB call inside for-each loop
- `bl.db.write_in_loop` — save() inside for-loop (N+1 writes)
- `bl.db.read_modify_write_no_lock` — missing @Version or FOR UPDATE
- `bl.db.unpaginated_endpoint` — List<T> return without Pageable

### Stateful PBT (v7.5+)

Echidna-inspired stateful property-based testing for Python classes:

```bash
loomscan stateful-pbt --repo . --target ShoppingCart
```

Discovers classes with mutator methods, generates random action sequences (up to 100 steps), checks invariants after each action.

### Multi-Call Analysis (v7.5+)

Cross-function call-chain bug detection:
- **Reentrancy**: external call + state write
- **Missing-auth-in-chain**: sensitive operation without auth check
- **TOCTOU**: check-then-act across function boundaries

```bash
loomscan multi-call --repo . --check all
```

### JSX Auth Coverage (v7.5+)

React/Next.js authorization coverage analysis:

```bash
loomscan jsx-auth --repo .
```

Detects HOC patterns (withAuth), hook patterns (useAuth), route guards (<ProtectedRoute>), and flags pages WITHOUT any auth wrapper.

### Merge Review (v6.2+)

```bash
loomscan merge-review --base main --head feature-branch
```

Shows new findings, resolved findings, blast radius, and recommendation (approve/request_changes/block).

### Dead Persistence Detection (v7.3+)

Finds entities saved to DB but never read anywhere in the codebase. Uses `codebase_understanding.py` entity-type tracking.

### Dynamic CVE Checker (v7.1+)

Detects dependencies from lock files (PyPI, npm, Maven, Go, Rust), queries OSV API, checks reachability in source code.

### Runtime Error Scanner (v5.21+)

Scans `.log` files for Java OOM, UUID errors, 500s, NPEs, SQLExceptions. Also scans `.java` for empty catch blocks, printStackTrace, System.exit.

---

## 12. Rule Management

### List Rule Packs

```bash
loomscan rules list
```

### Rule Pack Structure

```
loomscan/rules/packs/
├── java-production-incidents.yml  (308 rules — DB anti-patterns, prod errors)
├── java-security.yml              (core Java security)
├── java-deep.yml                  (deep Java analysis)
├── java-frameworks.yml            (Spring, JPA, etc.)
├── python-security.yml
├── python-deep.yml
├── javascript-security.yml
├── ai-security.yml                (12 LLM security rules)
├── framework-taint.yml            (IDOR, mass assignment, etc.)
├── owasp-top-10.yml
└── ... (42 packs total, 2,473 rules)
```

---

## 13. GNN-on-CPG

### How It Works

1. **CPG builder**: AST nodes + AST edges + data-flow edges (def→use) + call edges
2. **Node features**: 16-dim node type one-hot + 6 numeric (calls, branches, loops, sensitive tokens, unsafe libs, depth)
3. **GNN model**: 2-layer GCN with learned weights, global mean pooling, MLP head
4. **Training**: Binary cross-entropy on labeled findings (TP=1.0, FP=0.0)

### Multi-Language Support

| Language | CPG Method | Feature Space |
|----------|-----------|---------------|
| Python | Full AST (`ast.parse`) | 22-dim (same for all) |
| Java | Regex function extraction + simplified CPG | 22-dim |
| JavaScript/TypeScript | Regex function extraction | 22-dim |
| Go | Regex function extraction | 22-dim |
| C/C++ | Regex function extraction | 22-dim |
| Rust | Regex function extraction | 22-dim |

### Fallback

If torch/torch-geometric not installed, falls back to HeuristicRiskScorer (hand-tuned logistic regression) with a warning.

---

## 14. Restored Modules (v7.5+)

Three modules were deleted in v7.4.0 (strategic mistake) and restored in v7.5.0:

| Module | LOC | CLI Command | What It Catches |
|--------|-----|-------------|-----------------|
| `jsx_auth.py` | 219 | `loomscan jsx-auth` | Pages without auth wrappers |
| `stateful_pbt.py` | 262 | `loomscan stateful-pbt` | Multi-step state bugs |
| `multi_call.py` | 322 | `loomscan multi-call` | Reentrancy, missing-auth chains, TOCTOU |

All three are wired into `loomscan check --full` (fire automatically when matching file types are present).

---

## 15. Troubleshooting

### "semgrep not installed" warning

Without semgrep, ~914 advanced rules are silently skipped. Install with:

```bash
pip install loomscan[full]  # or pip install loomscan[semgrep]
```

### "torch not installed" warning

The GNN falls back to HeuristicRiskScorer. Install with:

```bash
pip install loomscan[full]  # or pip install loomscan[gnn]
```

### "REFUSING to install" for binary tools

v7.3.4+: `loomscan install-tools` refuses to install binaries without SHA256 verification. All 7 binary tools now have `checksum_url` set. If the checksum fetch fails:

```bash
# Override (NOT RECOMMENDED)
LOOMSCAN_ALLOW_UNVERIFIED_INSTALL=1 loomscan install-tools
```

### Feedback loop (scanning own output)

LoomScan uses `_paths.py` with `DEFAULT_SKIP_DIRS` (31 directories) to prevent scanning its own output. If you see findings from `.loomscan-cache/` files, ensure you're running v7.5.1+.

---

## 16. Internals

### Architecture

```
loomscan/
├── orchestrator.py          # Main pipeline (run_full / run)
├── yaml_engine.py           # YAML rule pack execution
├── rules/__init__.py        # Pack registration and selection
├── business_logic_miner.py  # Cross-line BL pattern detection
├── codebase_understanding.py # Entity tracking + dead persistence
├── gnn_cpg.py               # Real GNN (torch-geometric)
├── brain/                   # Fuzzy aggregation + Bayesian
│   ├── it2_fis.py           # Interval type-2 FIS
│   ├── bayesian.py          # BBN + ExplainableAggregator
│   └── membership.py        # IT2 membership functions
├── cli.py                   # CLI commands (3,600+ LOC)
├── installer.py             # Tool installation with SHA256
├── report/                  # HTML/JSON/SARIF generators
├── layers/                  # Analysis layers
│   ├── l0_fast.py           # SAST (YAML rules)
│   ├── l8_autofix.py        # Auto-fix patterns
│   └── ...
├── v4_aggregator.py         # v7.5.6: Replaces v4_restored.py
└── rules/packs/             # 42 YAML rule packs (2,473 rules)
```

### Pipeline Flow

1. **L0 Fast (SAST)** — 2,473 YAML rules via Rust/Python engine
2. **L0b Supply Chain** — dependency CVE checking via OSV API
3. **Advanced Detection** — TOCTOU, BL miner, field taint, integer overflow, GNN
4. **L5 Policy** — config checks (Spring Actuator, CORS, etc.)
5. **L8 Auto-Fix** — 107 fix patterns
6. **Aggregation** — IT2-FIS + BBN + counterfactual → final decision
7. **Report** — HTML/JSON/SARIF

### Deprecation Notices

- `v4_restored.py` — deprecated since v7.4. v7.5.6: orchestrator now imports from `v4_aggregator.py` instead. Will be removed in v8.0.
- `GNNOnCPG` class name — renamed to `HeuristicRiskScorer` in v7.3.4. Backward-compat alias preserved. Will be removed in v8.0.
