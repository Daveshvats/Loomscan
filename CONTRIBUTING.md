# Contributing to LoomScan

Thank you for your interest in contributing to LoomScan! This document covers
everything you need to know to get started.

## Code of Conduct

Be kind. Be constructive. Assume good intent. We're all here to make code
analysis better.

## Getting Started

### Prerequisites

- Python 3.12+
- `pip` (latest)
- `git`

### Setup

```bash
# Clone
git clone https://github.com/loomscan/loomscan.git
cd loomscan

# Install in development mode (full feature set)
pip install -e ".[full]"

# Verify installation
loomscan doctor
loomscan --version
```

### Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run a specific test file
python -m pytest tests/test_v4_restored.py -v

# Run with coverage
python -m pytest tests/ --cov=loomscan --cov-report=term-missing
```

### Running LoomScan on Itself

```bash
# Scan LoomScan's own source code (eat your own dog food)
loomscan check --full

# Quick diff scan (just changed files)
loomscan check
```

## How to Contribute

### Reporting Bugs

1. Search existing issues to avoid duplicates.
2. Open a new issue with:
   - LoomScan version (`loomscan --version`)
   - Python version (`python --version`)
   - OS (macOS / Linux / Windows)
   - Minimal reproduction steps
   - Expected vs actual behavior
   - Relevant logs (use `--verbose` for more output)

### Suggesting Enhancements

1. Open an issue with the `enhancement` label.
2. Describe the use case — not just the solution.
3. If possible, sketch the API (CLI flags, config keys, Python API).

### Pull Requests

1. **Fork & branch**: Create a feature branch from `main`:
   ```bash
   git checkout -b feat/my-feature
   ```
2. **Write code**: Follow the style below.
3. **Write tests**: Every new feature needs tests. Every bug fix needs a
   regression test.
4. **Run tests locally**:
   ```bash
   python -m pytest tests/ -v
   ```
5. **Update docs**: If your change affects user-facing behavior, update
   `README.md` and `CHANGELOG.md`.
6. **Commit**: Use clear commit messages:
   ```
   feat(java): add @Transactional rollbackFor detection
   fix(installer): SHA256 verification now refuses unverified installs
   docs(guide): refresh for v7.4
   refactor(orchestrator): extract _run_advanced_research_engines
   ```
7. **Open PR**: Link the issue, describe the change, list testing done.

## Code Style

### Python

- **Formatter**: `black` (line length 100)
- **Linter**: `ruff` (replaces flake8 + isort)
- **Type checker**: `mypy` (strict for new code; existing files are
  progressively being typed)

```bash
# Format
black loomscan/ tests/
ruff check loomscan/ tests/ --fix

# Type check
mypy loomscan/new_module.py
```

### File Organization

- One class/concept per file when practical.
- Files > 500 LOC should be split (we're working on `cli.py` and
  `l8_autofix.py` — see v7.4 changelog).
- Use `from __future__ import annotations` at the top of every file.
- Group imports: stdlib → third-party → local.

### Rule Packs (YAML)

Rule packs live in `loomscan/rules/packs/`. Each pack:

- Has a header comment explaining scope, design notes, and overlap with
  other packs.
- Uses single-quoted YAML strings (backslashes are literal).
- Patterns MUST match a single line of source — the YAML engine scans
  line-by-line. Do NOT use `\n` or DOTALL constructs.
- For multi-line patterns, use the BL-miner (`business_logic_miner.py`)
  instead.
- Every rule has: `id`, `pattern`, `severity`, `message`, `metadata.cwe`.

### Tests

- Test files: `tests/test_<feature>.py`
- Use `pytest` fixtures, not `unittest` classes.
- Name tests `test_<what>_<condition>`:
  ```python
  def test_enum_valueof_fires_on_user_input():
      ...
  ```
- Every bug fix gets a regression test that would have caught the bug.

## Architecture Overview

LoomScan has 4 layers:

1. **L0 Fast (SAST)** — YAML regex rules + Rust core. 2,473 rules across 42 packs.
2. **L0b Supply Chain** — dependency CVE checking via OSV API.
3. **L5 Policy** — config checks (Spring Actuator, CORS, etc.).
4. **L8 Auto-Fix** — 107 fix patterns that patch code automatically.

The orchestrator (`loomscan/orchestrator.py`) runs all layers and aggregates
findings through an interval type-2 fuzzy inference system (the "brain").

Key modules:
- `loomscan/orchestrator.py` — main pipeline
- `loomscan/yaml_engine.py` — rule pack execution
- `loomscan/rules/__init__.py` — pack registration and selection
- `loomscan/business_logic_miner.py` — cross-line BL pattern detection
- `loomscan/codebase_understanding.py` — entity tracking + dead-persistence
- `loomscan/brain/` — fuzzy aggregation + Bayesian second opinion
- `loomscan/cli.py` — CLI commands
- `loomscan/report/` — HTML/JSON/SARIF report generators

## Adding a New Rule Pack

1. Create `loomscan/rules/packs/<name>.yml`:
   ```yaml
   rules:
     - id: my-rule
       pattern: 'some\s+regex'
       severity: medium
       message: "Description of the issue."
       metadata:
         cwe: CWE-XXX
         owasp: A0X
   ```
2. Register it in `loomscan/rules/__init__.py`:
   - Add to `BUILTIN_PACKS` dict.
   - Add to `get_all_packs_for_files()` for the appropriate file extensions.
3. Write tests in `tests/test_<name>.py`.
4. Update `CHANGELOG.md`.

## Adding a New Detection Engine

1. Create `loomscan/<engine>_detector.py` with a `scan_repo_<engine>(repo_root)`
   function returning `List[Finding]`.
2. Wire it into `orchestrator.py` in `_run_advanced_research_engines()`.
3. Add a test fixture with a known-vulnerable sample.
4. Update `CHANGELOG.md`.

## Release Process

1. Update version in `pyproject.toml` and `loomscan/__init__.py`.
2. Update `CHANGELOG.md` with the new version section.
3. Update `README.md` version header.
4. Run full test suite: `python -m pytest tests/ -v`.
5. Create tarball: `tar -czf download/loomscan-vX.Y.Z.tar.gz loomscan/ pyproject.toml README.md LICENSE GUIDE.md SECURITY.md CHANGELOG.md CONTRIBUTING.md`
6. Tag: `git tag v7.4.0 && git push origin v7.4.0`.
7. PyPI: `python -m build && twine upload dist/*`.
8. GitHub Release with changelog notes.

## Getting Help

- **Issues**: <https://github.com/loomscan/loomscan/issues>
- **Discussions**: <https://github.com/loomscan/loomscan/discussions>
- **Security**: see `SECURITY.md` (DO NOT open public issues for vulnerabilities)

## License

By contributing, you agree that your contributions will be licensed under the
MIT License (see `LICENSE`).
