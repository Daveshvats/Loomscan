# LoomScan — Static + Test + Constraint Analysis

> **v5.9** — A deterministic-first, type-2 fuzzy aggregated bug detection pipeline with **2,095 rules across 40 packs covering 24 languages**, **107 auto-fix patterns**, **275 secret detection patterns**, **10 unique differentiators**, and **80+ CLI commands**. Free, offline, and production-ready. Native YAML rule engine (no semgrep dependency), multi-language CPG def-use chains, incremental CPG caching, SARIF Pro tier with threadFlow, **premium animated TUI mascot (real pixel-art spider via Kitty/iTerm2 inline-image protocols, with ASCII fallback) + progress bar**, **optional Rust regex core** for 10-50× faster pattern matching, and a **3-tier install model** (`pip install loomscan` / `[full]` / `[fast]`).

## Quick Start

```bash
# 3-tier install model — pick the tier that fits your needs:

# Tier 1: Basic (pure Python, works everywhere, no compilation)
pip install loomscan

# Tier 2: Full analysis (adds tree-sitter for CPG/def-use chains)
pip install loomscan[full]

# Tier 3: Performance (adds Rust core for 10-50x faster scanning)
pip install loomscan[fast]

# Verify your install (shows which tier is active):
loomscan doctor

# One-command quickstart (creates config, runs scan, shows summary):
loomscan quickstart /path/to/your/code

# Or step by step:
loomscan init                    # Create .loomscan.yaml config
loomscan check --full            # Scan the full repo (with Loomy the spider mascot!)
loomscan check --full --no-tui   # CI mode (no animation)
loomscan check --full --summary  # Compact grouped output
loomscan gate --full --preset strict  # Quality gate (SonarQube-style)
loomscan fix --apply             # Apply auto-fixes
loomscan dashboard --repo . --open   # Generate HTML dashboard + open in browser
```

## What's New in v5.9

Loomy gets a premium graphics upgrade, and the doctor gets smarter.

| Change | What it does |
|--------|--------------|
| **Premium mascot via inline-image protocols** | On Kitty, iTerm2, WezTerm, VS Code, and Ghostty terminals, Loomy is now rendered as **real pixel-art PNG frames** (24-frame animation, anti-aliased, 200×200) using the Kitty graphics protocol or iTerm2 inline-image protocol. No more blocky ASCII — it's a real animated spider. Falls back to ASCII art on terminals without image support. |
| **Terminal auto-detection** | `loomscan/tui/image_render.py` auto-detects which protocol your terminal supports (Kitty / iTerm2 / Sixel / ASCII) via `$TERM`, `$TERM_PROGRAM`, `$LC_TERMINAL` env vars. No configuration needed — it just works. |
| **Doctor shows mascot renderer** | `loomscan doctor` now reports which terminal protocol is active and how many animation frames are loaded, so you can verify the premium mascot is working. |
| **Doctor skfuzzy fix** | Fixed the cosmetic bug where `scikit-fuzzy` showed as `[FAIL]` even when installed — the doctor now checks the correct import name (`skfuzzy`) and shows the pip package name (`scikit-fuzzy`) in suggestions. |
| **Spider GIF optimized** | Original 4.7MB / 120-frame GIF → 112KB optimized GIF + 131KB of 24 PNG frames (243KB total assets). Ships in the pip package via `[tool.setuptools.package-data]`. |

```bash
# On a supporting terminal (Kitty/iTerm2/WezTerm/VS Code/Ghostty):
loomscan check --full
# → Loomy appears as a real animated pixel-art spider 🕷️

# On a plain terminal (Linux console, CI log):
loomscan check --full
# → Loomy falls back to ASCII spider (still animated, 8-frame weaving cycle)

# Check which renderer is active:
loomscan doctor
# → "TUI mascot: [IMAGE] Terminal protocol: kitty — Loomy renders as real pixel art!"
```

## What's New in v5.8

The mascot is now a real spider, the install is now 3-tier, and there's a `doctor` command.

| Change | What it does |
|--------|--------------|
| **Loomy redesigned as a real spider** | The mascot is now clearly a SPIDER — 8 articulated legs, abdomen + cephalothorax, spinneret, fangs. An 8-frame weaving cycle shows a web growing from 2 anchor strands → full orb web with radial spokes + sticky capture spiral. The spider's eyes change from `-_-` (focused) to `^ ^` (happy) when the web is complete. |
| **3-tier install model** | `pip install loomscan` (Tier 1, pure Python) / `pip install loomscan[full]` (Tier 2, +tree-sitter) / `pip install loomscan[fast]` (Tier 3, +Rust core). All dependencies have pre-built wheels — no compilation needed on any platform. |
| **`loomscan doctor` command** | Health check that shows install tier, Rust core status, tree-sitter availability, rule count, and external tools. Exit code 0/1/2 indicates health. Run after install to verify everything works. |
| **Rust wheel CI workflow** | `.github/workflows/build-rust-wheels.yml` builds pre-built binary wheels for Linux x86_64/aarch64, macOS Intel/ARM, and Windows x86_64. Users get `pip install loomscan[fast]` with zero compilation. |
| **`tree-sitter` moved to `[full]`** | v5.7 required tree-sitter as a hard dependency. v5.8 makes it optional (`pip install loomscan[full]`). Tier 1 install is now pure Python and works on any platform without compilation. |

## What's New in v5.7

Two big UX wins + the Rust core comes online:

| Change | What it does |
|--------|--------------|
| **Animated TUI mascot (Loomy)** | While the pipeline runs, an ASCII spider "Loomy" weaves a web in your terminal — 6-frame walk cycle, phase-aware speech bubbles. Like the mascots in claude-code / opencode. Auto-disabled in CI / pipes / `--no-tui`. |
| **Progress bar** | Rich-powered 7-stage tracker: `Layers → Taint & CPG → Research Engines → Multi-lang → Precision → FIS Brain → AutoFix`. Shows `[████░░░] N/7` + live findings counter + elapsed seconds. No more "is it stuck?" |
| **`--no-tui` flag** | Disables mascot + progress bar for CI logs / piping to file. |
| **Rust regex core (compiled)** | `rust-core/` now compiles to a real native extension via `maturin`. `yaml_engine.py` auto-detects the Rust engine and uses it for 10-50× faster regex matching, with seamless fallback to Python `re`. |
| **README honest version** | README header finally matches `pyproject.toml` (was stuck on v5.4 since v5.4). |

```bash
loomscan check --full                    # with mascot + progress bar
loomscan check --full --no-tui           # CI mode (plain output)
loomscan check --full --json             # JSON output (auto-disables TUI)
```

## What Makes LoomScan Unique

LoomScan has **9 capabilities no competitor offers**:

| # | Feature | What It Does |
|---|---------|-------------|
| 1 | **IT2-FIS Brain** | Type-2 fuzzy inference system with 50 rules. Produces confidence *intervals* (not point estimates). Aggregates severity, confidence, blast radius, exploitability, and source-layer reliability into BLOCK/WARN/PASS/UNCERTAIN decisions. |
| 2 | **LLM-Verify** | LLM proposes hypotheses ("function crashes on None input"); LoomScan verifies by *execution*. Only confirmed bugs are reported. PRM-gated (process reward model scores the LLM's reasoning). |
| 3 | **Counterfactual Mutation** | Mutates the code (removes lines, injects guards) and re-runs detectors. If the finding disappears → true positive (boost confidence). If it persists → false positive (demote). |
| 4 | **Metamorphic Testing** | Oracle-free bug detection: `sort(sort(x)) == sort(x)`, `hash(x) == hash(x)`. Catches semantic bugs no test oracle can. |
| 5 | **Knowledge Graph** | Builds a codebase structure graph (1,400+ nodes for a typical project). `loomscan impact --changed file.py` shows blast radius (which functions are affected by your change). |
| 6 | **Rule Auto-Mining** | `loomscan mine` scans git history for bug-fix commits and auto-generates Semgrep rules from the diff. Every bug you've ever fixed becomes a permanent rule. |
| 7 | **Spec Mining** | `loomscan spec` mines API usage patterns from your codebase (e.g., "open() is always followed by close()") and flags deviations. Adaptive — learns from your code, not from generic rules. |
| 8 | **--uncertain Flag** | `loomscan check --uncertain` shows only 30-70% confidence findings — the ones worth human review. No competitor has this. |
| 9 | **9-Level Strictness** | PHPStan-inspired strictness levels (1-9). Level 1 = only critical findings; Level 9 = everything including style issues. |

## Rule Coverage

| Category | Count | Details |
|----------|-------|---------|
| **YAML pack rules** | 1,995 | 39 packs across 24 languages |
| **Secret patterns** | 275 | AWS, Stripe, GitHub, Slack, OpenAI, Anthropic, GCP, Azure, +200 more |
| **Auto-fix patterns** | 107 | Python, JS, Java, Go, C/C++, Rust, PHP, Ruby, C#, Kotlin, SQL, Bash, Dart, Swift, Scala |
| **CPG queries** | 6 | Taint flows, unused variables, auth patterns, complexity, def-use chains, cross-function taint |
| **Taint sinks** | 28 | Cross-file source→sink patterns |
| **Typestate protocols** | 5 | File, connection, payment, session, transaction |

## Supported Languages (24)

Python, JavaScript, TypeScript, Go, Java, Rust, C, C++, PHP, Ruby, C#, Swift, Scala, Kotlin, SQL, Bash, Dart, Lua, R, Haskell, Elixir, Objective-C, Groovy, Julia, Perl, COBOL

## CLI Commands (77)

### Core
```bash
loomscan check [--full] [--json] [--sarif --output file] [--strictness N] [--uncertain]
loomscan gate [--full] [--preset strict|balanced|permissive|custom] [--max-critical N] [--max-high N]
loomscan fix [--apply] [--finding-id ID]
loomscan init / install-tools / doctor
```

### IDE Integration
```bash
loomscan lsp                    # Start LSP server (VS Code / JetBrains / Neovim)
loomscan watch                  # Incremental scanning with sub-second feedback
loomscan playground             # Web UI for testing regex rules (localhost:8765)
```

### Analysis
```bash
loomscan cpg --query taint|unused|auth|complexity|def_use|cross_func
loomscan typestate             # State machine violations
loomscan metamorphic           # Oracle-free bug detection
loomscan differential          # Refactor verification
loomscan llm-verify            # LLM proposes, LoomScan verifies by execution
loomscan impact --changed file.py  # Blast radius analysis
loomscan spec                  # Spec mining (adaptive API pattern learning)
loomscan mine                  # Rule auto-mining from git history
```

### Rules
```bash
loomscan rules list             # List all 39 built-in packs
loomscan rules show <pack>      # Show rules in a pack
loomscan rules pull <pack>      # Pull external pack
loomscan rules submit --pack my-rules.yml --name my-pack --language python  # Submit community rules
```

### CI/CD
```bash
loomscan bot --pr 42 --token $GITHUB_TOKEN  # PR comment bot (inline review comments)
loomscan check --sarif --output loomscan.sarif   # SARIF for GitHub Code Scanning
loomscan gate --preset strict                 # Quality gate (exit 0=pass, 1=fail)
```

### Quality
```bash
loomscan strictness --level N   # Set strictness (1-9)
loomscan code-quality           # Multi-language code quality
loomscan config-scan            # Scan config files for secrets
loomscan duplicates             # Code duplication detection
loomscan deadcode               # Dead code analysis
loomscan hotspot                # Security hotspot detection
```

## IDE Extensions

### VS Code
```bash
code --install-extension editor/vscode-loomscan/loomscan-0.2.0.vsix
```
- Real-time diagnostics via LSP
- Hover shows rule details + fix suggestions
- Code actions: "Apply LoomScan fix" (quickfix)
- 6 commands: CheckRepo, CheckFile, ApplyFix, ShowUncertain, Gate, Restart
- 17 language activations

### JetBrains (IntelliJ, PyCharm, WebStorm, etc.)
```bash
cd editor/intellij-loomscan && ./gradlew buildPlugin
# Install: Settings > Plugins > Install from Disk > build/distributions/*.zip
```
- LSP support via IntelliJ 2023.1+ platform
- 7 actions, settings panel, tool window, status bar widget
- CI builds automatically via `.github/workflows/build-jetbrains.yml`

## Architecture

```
git diff / --full
   │
   ├─► L0  Fast hooks (1,995 YAML rules + 275 secret patterns + 107 autofix)
   ├─► L0  CPG cross-file taint tracking + def-use chains
   ├─► L0  Typestate analysis (5 protocols)
   ├─► L0  Spec mining (adaptive API pattern learning)
   ├─► L0b Supply chain (pip-audit, npm audit, osv-scanner, cargo audit, govulncheck)
   ├─► L0e IaC scanning (Dockerfile, K8s, Terraform, CloudFormation, GitHub Actions)
   ├─► L0f Commit risk (size, time, message, author, reverts)
   ├─► L1  Property tests (Hypothesis) + Metamorphic tests + Differential tests
   ├─► L2  Mutation testing (mutmut)
   ├─► L3  Invariant checks (Daikon-style)
   ├─► L4  Directed greybox fuzz (Atheris)
   ├─► L5  Policy-as-code (OPA/Rego)
   ├─► L6  Symbolic verification (Kani for Rust)
   ├─► L7  Deterministic simulation
   ├─► L8  Auto-Fix (107 patterns across 15 languages)
   │
   ▼
┌─────────────────────────────────────────────────────┐
│  IT2-FIS Aggregation Brain (50 fuzzy rules)         │
│  + Bayesian second opinion (BBN with CPTs)          │
│  + Counterfactual mutation verification             │
│  + LLM-as-oracle (PRM-gated, execution-verified)    │
│  Output: BLOCK / WARN / PASS / UNCERTAIN            │
│  + Confidence intervals (not point estimates)       │
└─────────────────────────────────────────────────────┘
   │
   ▼
SARIF 2.1.0 + Rich TUI + HTML + JSON + CycloneDX SBOM + SPDX SBOM
```

## Quality Gates (SonarQube-style)

```bash
# Presets
loomscan gate --full --preset strict       # 0 critical, 0 high, 5/1k LOC
loomscan gate --full --preset balanced     # 0 critical, 5 high, 10/1k LOC (DEFAULT)
loomscan gate --full --preset permissive   # 5 critical, 20 high, 20/1k LOC
loomscan gate --full --preset custom --max-critical 0 --max-high 10

# Exit codes: 0=pass, 1=fail, 2=error, 3=scanner failure
```

## Monorepo Support

```yaml
# .loomscan.yaml
workspaces:
  - "apps/*"
  - "packages/*"
workspace_exclude:
  - "**/node_modules/**"
```

```bash
loomscan monorepo --list     # List resolved workspaces
loomscan monorepo --scan     # Scan each workspace, report findings
loomscan monorepo --add 'services/*'
```

## GitHub Actions Integration

```yaml
# .github/workflows/loomscan.yml
- name: Install LoomScan
  run: pip install --user .
- name: Run LoomScan
  run: loomscan check --sarif --output loomscan.sarif --strictness 5
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: loomscan.sarif
```

```yaml
# .github/workflows/loomscan-bot.yml — PR comment bot
- name: Run LoomScan PR Bot
  run: loomscan bot --token ${{ secrets.GITHUB_TOKEN }}
```

## Competitive Position

| Axis | LoomScan v4.43 | Semgrep | SonarQube | CodeQL |
|------|-----------|---------|-----------|--------|
| Total rules | ~2,700 | 3,000+ | 5,000+ | 1,500+ |
| Languages | 24 | 30+ | 30+ | 6 (deep) |
| Auto-fix | 107 | ~50 | ~200 | ❌ |
| Secrets | 275 | 200+ | enterprise | ❌ |
| FIS aggregation | ✅ | ❌ | ❌ | ❌ |
| LLM-verify | ✅ | ❌ | ❌ | ❌ |
| Rule mining | ✅ | ❌ | ❌ | ❌ |
| Spec mining | ✅ | ❌ | ❌ | ❌ |
| Free + offline | ✅ | ✅ CE | ⚠️ limits | ✅ |
| IDE plugins | VS Code + JetBrains | ✅ | SonarLint | ❌ |

## Test Suite

- **717 tests passed**, 35 skipped (tree-sitter grammars), 0 failed
- 291 smoke tests across v4.33-v4.43
- E2E tests for: SARIF, cross-file taint, max-files override, Docker healthcheck, LSP hover/code actions, spec mining, def-use chains, fast_regex, rules submit, PR bot, playground, monorepo

## License

MIT.
