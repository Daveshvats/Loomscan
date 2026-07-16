# LoomScan v7.3.2 🕷️

> **Static + Test + Constraint Analysis** — 2,473 rules across 42 packs covering 24 languages. 76+ detection engines. **20/20 (100%) vulnerability detection rate.** Free, offline, production-ready. Rich CLI display with real-time progress. Rust core for 10-50× faster scanning. Pre-merge branch analysis with blast radius. CVE enrichment (16 CWEs, 40+ CVEs). Runtime error scanner. AI/LLM security. Integer overflow detection. Latest CVE rules (2024-2025). VS Code + JetBrains extensions.

## Quick Start

```bash
# Install (pure Python, works everywhere)
pip install loomscan

# Full install (Rust core + tree-sitter + TUI + everything)
pip install loomscan[full]

# Scan your code
loomscan check --full

# Pre-merge analysis (see what a branch introduces)
loomscan merge-review --base main

# Check system health
loomscan doctor
```

## Installation Tiers

| Tier | Command | What You Get |
|------|---------|-------------|
| **1. Basic** | `pip install loomscan` | All 2,473 rules, Rich CLI display, 75+ engines, HTML/SARIF/JSON reports |
| **2. Full** | `pip install loomscan[full]` | + tree-sitter (CPG/def-use), Rust core (10-50× faster), TUI, pillow |
| **3. All** | `pip install loomscan[all]` | + semgrep, mutation testing, LLM verify, fuzz, premium image rendering |

## What `loomscan check --full` Runs

When you run `loomscan check --full`, ALL of these execute:

### Analysis Modules (18 total)
| Module | What It Detects |
|--------|----------------|
| L0 Fast (SAST) | 2,473 YAML rules via Rust/Python engine |
| Secrets | 275 secret patterns (AWS, Stripe, GitHub, +200 more) |
| Taint Tracking | Interprocedural source→sink (Python, JS, Java, Go) |
| CPG Queries | Code Property Graph: taint flows, unused vars, auth patterns |
| Metamorphic | Oracle-free bug detection (sort(sort(x))==sort(x)) |
| Code Quality | 111+ rules across 8 languages |
| Dead Code | Runtime dead code analysis |
| Nullness | Sound null dereference analysis |
| Root Cause | Root cause clustering |
| Impact | Blast-radius analysis (knowledge graph) |
| Duplicates | Find duplicated code blocks |
| Doc Audit | Documentation audit |
| Supply Chain | Dependency CVEs (pip-audit, npm audit, govulncheck, cargo-audit) |
| Flawfinder | C/C++ dangerous functions (43 patterns) |
| Malicious | Malicious code pattern detection |
| PII | PII data detection |
| Contracts | Design-by-contract verification |
| Architecture | Architecture rule enforcement |

### Advanced Engines (v6.0-v6.2)
| Engine | What It Detects | Unique? |
|--------|----------------|---------|
| **TOCTOU Detector** | Race conditions: check-then-act on files/DB/auth | ✅ No competitor has this |
| **Business Logic Miner** | Negative quantity, price from user input, missing balance check | ✅ No competitor has this |
| **Field Taint Tracker** | IDOR, mass assignment, privilege escalation (field-level) | Tied with CodeQL |
| **Deep Dataflow** | JS/Java source→sink taint (tracks through assignments/calls) | ✅ Beyond regex |
| **Runtime Error Scanner** | Java OOM, UUID errors, 500s in .log files | ✅ No competitor has this |
| **Counterfactual Mutation** | Verifies findings by mutating code (9 languages) | ✅ No competitor has this |
| **CVE Enrichment** | Maps findings to known CVEs (Log4Shell, Spring4Shell, etc.) | ✅ Context-aware |
| **Merge Review** | Pre-merge: new vs resolved findings + blast radius + recommendation | ✅ No competitor has this |

### Vulnerability Coverage: 19/20 (95%)
| # | Vulnerability | Status | Engine |
|---|--------------|--------|--------|
| 1 | SQL Injection | ✅ | YAML + taint + OWASP |
| 2 | Command Injection | ✅ | YAML + code_quality |
| 3 | Hardcoded Secret | ✅ | Regex + entropy |
| 4 | Missing Auth | ✅ | Auth detector + BL |
| 5 | Race Condition (TOCTOU) | ✅ | TOCTOU detector (AST) |
| 6 | Integer Overflow | ❌ | Needs type inference (v7.2) |
| 7 | Business Logic (neg qty) | ✅ | Domain-aware BL miner |
| 8 | Missing Transaction | ✅ | Typestate protocol |
| 9 | Log Injection | ✅ | Code quality + CPG |
| 10 | Insecure Random | ✅ | YAML + crypto |
| 11 | Path Traversal | ✅ | Hotspot + YAML |
| 12 | SSRF | ✅ | Hotspot + YAML + cloud metadata |
| 13 | Timing Attack | ✅ | YAML rules |
| 14 | Resource Leak | ✅ | Typestate |
| 15 | Error Swallowing | ✅ | Code quality + AST |
| 16 | ReDoS | ✅ | YAML rules |
| 17 | Mass Assignment | ✅ | Field taint tracker |
| 18 | Missing Rate Limit | ✅ | YAML rules |
| 19 | IDOR | ✅ | Field taint + YAML |
| 20 | Info Disclosure | ✅ | OWASP + CWE-200 |

## CLI Commands (80+)

### Core Commands
```bash
loomscan check --full                    # Full-repo scan (all 18 modules)
loomscan check --full --engine rust      # Force Rust engine (10-50× faster)
loomscan check --full --engine all       # Run BOTH Rust + semgrep
loomscan check --full --engine semgrep   # Force semgrep (full pattern support)
loomscan check --full --exclude tests,vendor  # Exclude folders (comma-separated)
loomscan check --full --strictness 7     # Set strictness (1-9, default: 7)
loomscan check --full --sarif            # Generate SARIF report
loomscan check --full --json             # JSON output
loomscan check --full --summary          # Compact grouped output
loomscan merge-review --base main        # Pre-merge analysis
loomscan doctor                          # System health check
loomscan quickstart /path/to/code        # First-time setup + scan
loomscan init                            # Create .loomscan.yaml config
loomscan fix --apply                     # Apply auto-fixes
loomscan gate --full --preset strict     # Quality gate
```

### Analysis Commands (individual modules)
```bash
loomscan taint              # Taint tracking
loomscan cpg                # CPG queries
loomscan metamorphic        # Metamorphic tests
loomscan nullness           # Null dereference analysis
loomscan deadcode           # Dead code
loomscan duplicates         # Duplicate code
loomscan rca                # Root cause analysis
loomscan impact --changed file.py  # Blast radius
loomscan architecture       # Architecture enforcement
loomscan contracts          # Contract verification
loomscan typestate          # State machine violations
loomscan consistency        # Pattern consistency
loomscan flawfinder         # C/C++ dangerous functions
loomscan malicious          # Malicious patterns
loomscan pii                # PII detection
loomscan secrets            # Secret detection
loomscan supply-chain       # Dependency CVEs
loomscan sbom               # Software Bill of Materials
```

### Security Commands
```bash
loomscan missing-patches    # Unpatched CVEs
loomscan history-scan       # Git history secrets
loomscan toxicity           # Code toxicity
loomscan ffi-check          # FFI boundary analysis
loomscan doc-audit          # Documentation audit
loomscan modern             # Modern attack surfaces
loomscan iac                # IaC (Terraform/Docker/K8s)
loomscan config-scan        # Config file security
loomscan crypto             # Crypto audit
loomscan concurrency        # Concurrency bugs
loomscan business-logic     # Business logic extraction
loomscan code-quality       # Code quality (111+ rules)
```

### Rule Management
```bash
loomscan mine               # Auto-mine rules from git history
loomscan spec               # Spec mining — mine API usage patterns
loomscan rule-lint          # Lint custom rules
loomscan playground         # Rule playground
loomscan submit --pack file.yml --name my-pack  # Submit rule pack
```

### System
```bash
loomscan install-tools      # Install gitleaks, semgrep, opa, etc.
loomscan monorepo --add 'apps/*'  # Monorepo workspace
loomscan watch              # Watch + re-scan on save
loomscan lsp                # LSP server for IDE integration
loomscan dashboard --open   # HTML dashboard
loomscan bot                # GitHub PR comment bot
loomscan precision          # Precision engine tuning
loomscan profile            # Configuration profiles
loomscan strictness --level 7  # Set strictness
loomscan baseline           # Issue baseline management
loomscan cache --clear      # Clear cache
loomscan audit              # Audit log
```

## Engine Selection (`--engine`)

| Engine | Speed | Coverage | When to Use |
|--------|-------|----------|-------------|
| `auto` (default) | Fast | Regex rules | Default — uses Rust if available |
| `rust` | 10-50× faster | Regex rules | Large repos, CI/CD |
| `semgrep` | Medium | Full pattern support | Deep analysis (pattern-inside, metavariables) |
| `python` | Slowest | Regex rules | No dependencies, always works |
| `all` | Slowest | Both engines | Maximum coverage — runs Rust + semgrep, deduplicates |

**Features behind semgrep:** `pattern-inside`, `metavariable-regex`, `metavariable-pattern`, `focus-metavariable`, `pattern-not-inside`, `pattern-not-regex`. Without semgrep, these ~914 advanced rules are skipped (the remaining ~1,340 regex rules still fire).

## Exclude System

3 layers of exclusion:
1. **Default excludes** (36 patterns): node_modules, .git, build, dist, vendor, lock files, *.min.js, IDE configs
2. **`.loomscanignore` file** (auto-generated on first scan): Language-aware — Python gets `__pycache__/`, JS gets `node_modules/`, etc.
3. **`--exclude` flag**: `--exclude tests,vendor,docs` (comma-separated) or `--exclude tests --exclude vendor`

## Reports

After every scan, LoomScan generates:
- **HTML report** — dark theme, donut chart, filterable table, code graph, scan config details
- **SARIF report** — GitHub Code Scanning compatible
- **JSON report** — machine-readable, used by the HTML report

Reports are saved to `.loomscan-reports/`. HTML auto-opens in browser.

## Rule Packs (42 packs, 2,473 rules)

| Category | Packs | Rules |
|----------|-------|-------|
| Language security | 24 (python, java, js, go, c, rust, php, ruby, c#, swift, kotlin, scala, haskell, elixir, dart, lua, r, julia, perl, cobol, objectivec, groovy, bash, sql) | 800+ |
| Deep analysis | 8 (python-deep, java-deep, javascript-deep, java-production-incidents, semgrep-community-deep, etc.) | 800+ |
| Framework | 4 (framework-taint, java-frameworks, javascript-frameworks, python-frameworks) | 200+ |
| OWASP | 1 | 124 |
| AI/LLM security | 1 | 12 |
| Inspired by | 4 (spotbugs, detekt, luacheck, lintr) | 80+ |

## Unique Differentiators (11 — no competitor has all)

1. **IT2-FIS Brain** — Type-2 fuzzy inference with confidence intervals
2. **Counterfactual Mutation** — Verifies findings by mutating code (9 languages)
3. **Runtime Error Scanner** — Scans .log files for production errors
4. **TOCTOU Detector** — AST-based race condition detection
5. **Domain-Aware BL Miner** — Understands quantity, price, money, discount
6. **Field-Sensitive Taint** — IDOR + mass assignment + privilege escalation
7. **Merge Review** — Pre-merge analysis with blast radius
8. **CVE Enrichment** — Maps findings to known CVEs
9. **AI/LLM Security** — Prompt injection, tool use, API key detection
10. **--uncertain Flag** — Shows only 30-70% confidence findings
11. **9-Level Strictness** — PHPStan-inspired (1=critical only, 9=everything)

## Merge Review

```bash
# See what a branch introduces before merging
loomscan merge-review --base main

# JSON output for CI/CD
loomscan merge-review --base origin/main --json

# Exit codes: 0=approve, 1=block, 2=request_changes
```

Shows: new findings, resolved findings, blast radius, recommendation.

## GitHub Actions Integration

```yaml
# .github/workflows/loomscan.yml
name: LoomScan
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install loomscan[full]
      - run: loomscan merge-review --base origin/main --json || true
      - run: loomscan check --full --sarif
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: .loomscan-reports/result.sarif }
```

## Configuration

Create `.loomscan.yaml`:
```yaml
strictness_level: 7
workspace_exclude:
  - "**/node_modules/**"
  - "**/.git/**"
  - "**/vendor/**"
llm:
  enabled: false
brain:
  enable_bayesian: false
```

Or use `.loomscanignore` (same format as `.gitignore`):
```
tests/
vendor/
*.generated.go
```

## Requirements
- Python ≥ 3.12
- Git (for diff scanning)
- Optional: semgrep (`pip install semgrep`) for full pattern support
- Optional: loomscan-regex (Rust core, included in `[full]`)

## IDE Extensions

### VS Code Extension

The LoomScan VS Code extension provides real-time findings in your editor.

**Install:**
```bash
# From source
cd editor/vscode-loomscan
npm install
npm run build
# Package as .vsix
npx vsce package
# Install in VS Code
code --install-extension loomscan-0.2.0.vsix
```

**Or from VSIX file:**
1. Open VS Code
2. Go to Extensions (Ctrl+Shift+X)
3. Click "..." → "Install from VSIX..."
4. Select `editor/vscode-loomscan/loomscan-0.2.0.vsix`

**Features:**
- Real-time findings in Problems panel
- Hover tooltips with rule details, severity, and fix suggestions
- Quick-fix code actions for auto-fixable rules
- LSP integration (language server protocol)
- Automatic scan on file save

**Configuration (settings.json):**
```json
{
  "loomscan.enable": true,
  "loomscan.repoPath": "${workspaceFolder}",
  "loomscan.strictness": 7,
  "loomscan.scanOnSave": true,
  "loomscan.engine": "auto"
}
```

**Usage:**
1. Open a project folder in VS Code
2. LoomScan automatically scans on file save
3. Findings appear in the Problems panel (Ctrl+Shift+M)
4. Hover over a finding for details + fix suggestion
5. Click the lightbulb (💡) for quick-fix actions

### JetBrains Extension (IntelliJ IDEA, PyCharm, WebStorm, etc.)

The LoomScan JetBrains plugin provides findings in the IDE's inspection panel.

**Build from source:**
```bash
cd editor/intellij-loomscan
./gradlew buildPlugin
# The .zip file is in build/distributions/
```

**Install:**
1. Open IntelliJ IDEA (or PyCharm, WebStorm, etc.)
2. Go to Settings → Plugins → ⚙️ → "Install Plugin from Disk..."
3. Select the .zip file from `build/distributions/`

**Features:**
- Findings in the Inspections panel
- Inline annotations with severity icons
- Quick-fix intentions for auto-fixable rules
- Tool window with findings table
- Status bar widget showing finding count
- Project-level settings configurable in Settings → Tools → LoomScan

**Configuration:**
- Settings → Tools → LoomScan
  - Enable/disable LoomScan
  - Set repository path
  - Set strictness level (1-9)
  - Set YAML engine (auto/rust/semgrep/python)
  - Configure scan on save

**Usage:**
1. Open a project in IntelliJ
2. LoomScan scans on project open and file save
3. Findings appear as inspections (red/yellow/blue underlines)
4. View all findings in the LoomScan tool window (bottom panel)
5. Alt+Enter on a finding for quick-fix suggestions

## Vulnerability Classes Covered

LoomScan detects **20 of 20** common vulnerability classes (100%):

### Injection (6 classes)
| Class | CWE | Detection Method |
|-------|-----|-----------------|
| SQL Injection | CWE-89 | YAML rules + interprocedural taint + deep dataflow |
| Command Injection | CWE-78 | YAML rules + code quality + hotspots |
| Code Injection (eval) | CWE-94 | YAML rules + CPG taint + deep dataflow |
| LDAP Injection | CWE-90 | YAML rules (LDAP search filter) |
| XXE | CWE-611 | YAML rules (all XML parsers) |
| Log Injection | CWE-117 | Code quality + CPG taint |

### Authentication & Authorization (4 classes)
| Class | CWE | Detection Method |
|-------|-----|-----------------|
| Missing Auth | CWE-862 | Auth detector + business logic |
| IDOR | CWE-639 | Field-sensitive taint tracker |
| Mass Assignment | CWE-915 | Field taint + YAML rules |
| Privilege Escalation | CWE-269 | Field taint tracker (role/isAdmin from user input) |

### Data Protection (4 classes)
| Class | CWE | Detection Method |
|-------|-----|-----------------|
| Hardcoded Secrets | CWE-798 | 275 regex patterns + entropy |
| Path Traversal | CWE-22 | Hotspots + YAML rules |
| SSRF | CWE-918 | Hotspots + YAML + cloud metadata (169.254.169.254) |
| Info Disclosure | CWE-200 | OWASP pack + CWE-200 rules |

### Logic & Concurrency (5 classes)
| Class | CWE | Detection Method |
|-------|-----|-----------------|
| Race Condition (TOCTOU) | CWE-367 | AST-based TOCTOU detector |
| Business Logic (neg qty) | CWE-840 | Domain-aware BL miner |
| Missing Transaction | CWE-664 | Typestate protocol |
| Integer Overflow | CWE-190 | **v7.2: Integer overflow detector** |
| Timing Attack | CWE-208 | YAML rules (non-constant-time comparison) |

### Resource & Performance (3 classes)
| Class | CWE | Detection Method |
|-------|-----|-----------------|
| Resource Leak | CWE-404 | Typestate (file/connection/session protocols) |
| ReDoS | CWE-1333 | YAML rules (nested quantifiers) |
| Denial of Service | CWE-400 | YAML rules (OOM patterns, findAll, unbounded cache) |

### Database Anti-Patterns (v7.3 — unique, no competitor has this)
LoomScan is the **only SAST tool** that catches DB architectural anti-patterns in addition to SQL injection. v7.3 adds 65 YAML rules + 17 BL-miner patterns + dead-persistence detection across 8 categories:

| Category | Examples | Detection Method |
|----------|----------|------------------|
| **Transaction management** | `@Transactional` without `readOnly`/`rollbackFor`/`timeout` | 5 YAML rules |
| **Query inefficiency** | `findAll().size()`, `SELECT *`, JOIN FETCH without WHERE | 9 YAML rules |
| **JPA/EntityManager misuse** | `merge(new ...)`, manual `flush()`, `@Query(UPDATE)` without `@Modifying` | 5 YAML rules |
| **JPA entity design** | `@OneToMany` without `mappedBy`, `@Lob` without LAZY fetch | 5 YAML rules |
| **Locking & concurrency** | `PESSIMISTIC_WRITE` without timeout, `FOR UPDATE` without WHERE | 3 YAML rules |
| **Hibernate-specific** | deprecated `Criteria.list()`, `Query.iterate()` N+1 | 3 YAML rules |
| **Save patterns** | `save()` in loop, `saveAndFlush()`, DELETE FROM without WHERE | 5 YAML rules |
| **Cache & migration** | `@Cacheable` without `@CacheEvict`, `ddl-auto=update`, Liquibase `dropAll()` | 7 YAML rules |
| **Index & query plan** | `LIKE '%...'` leading wildcard, `NOT IN (SELECT...)`, `DISTINCT` with JOIN | 4 YAML rules |
| **Spring Data naming** | `findBy...Containing` (LIKE %...%), `findBy...IgnoreCase` (LOWER()) | 4 YAML rules |
| **BL-miner DB patterns** | load-all-for-count, load-entity-for-one-field, N+1-in-loop, read-modify-write-no-lock | 17 BL-miner patterns |
| **Dead persistence** | Entity saved but never read anywhere | codebase_understanding entity tracking |

### Production-Error Source Detection (v7.3)
Catches the 4 production errors (Jackson coercion, Invalid UUID, Enum constant, 57s timeout) **in source code BEFORE they reach production**:

| Production Error | Source Rule | Detection |
|------------------|-------------|-----------|
| `No enum constant` 500 | `java-enum-valueof-without-validation` | `Enum.valueOf(userInput)` without check |
| `Invalid UUID string: undefined` | `java-uuid-fromstring-no-try` | `UUID.fromString(userInput)` without try/catch |
| `Cannot coerce empty String` | `java-jackson-coerce-empty-string-config` | Jackson CoercionConfig check |
| 57-second timeout | `java-sync-blocking-endpoint-no-timeout`, `java-resttemplate-no-timeout`, `java-webclient-no-timeout`, `java-httpclient-no-timeout`, `java-thread-sleep-in-request`, `java-multipart-endpoint-no-async` | 6 source rules for timeout-prone patterns |

### Runtime Error Detection (unique — no competitor has this)
| Error | Source | Detection |
|-------|--------|-----------|
| OutOfMemoryError | .log files | Runtime error scanner (CRITICAL) |
| UUID errors | .log files | Runtime error scanner (HIGH) |
| HTTP 500 errors | .log files | Runtime error scanner (HIGH) |
| NullPointerException | .log files | Runtime error scanner (MEDIUM) |
| SQLException | .log files | Runtime error scanner (MEDIUM) |
| Empty catch blocks | .java source | YAML rules + code quality |

### Latest CVE Detection (2024-2025)
| CVE | Description | Detection |
|-----|-------------|-----------|
| CVE-2024-3094 | XZ Utils backdoor (sshd) | YAML rule |
| CVE-2024-21626 | runc container escape | YAML rule |
| CVE-2024-23897 | Jenkins CLI file read | YAML rule |
| CVE-2024-21887 | Ivanti Connect Secure RCE | YAML rule |
| CVE-2024-27198 | JetBrains TeamCity auth bypass | YAML rule |
| CVE-2024-6387 | OpenSSH RegreSSHion RCE | YAML rule |
| CVE-2024-37032 | Ollama path traversal | YAML rule |
| CVE-2024-1086 | Linux kernel nf_tables privesc | YAML rule |
| CVE-2025-1974 | Kubernetes ingress-nginx RCE | YAML rule |
| CVE-2021-44228 | Log4Shell (JNDI injection) | YAML rule + CVE enrichment |
| CVE-2022-22965 | Spring4Shell (ClassLoader) | YAML rule + CVE enrichment |

### AI/LLM Security (unique — no competitor has this)
| Risk | CWE | Detection |
|------|-----|-----------|
| Prompt injection | CWE-1039 | 12 AI/LLM security rules |
| Unrestricted tool use | CWE-94 | LLM tool use with exec/eval/file/network |
| API key exposure | CWE-798 | Hardcoded OpenAI/Anthropic/Cohere keys |
| System prompt override | CWE-1039 | User input in system role |
| Unbounded response | CWE-400 | Missing max_tokens |
| Hallucination risk | CWE-1041 | Temperature > 1.0 |
