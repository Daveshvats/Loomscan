# Security Policy

## Supported Versions

LoomScan is under active development. Security fixes are applied to the latest
release only. Users should always run the latest stable version.

| Version | Supported          |
|---------|--------------------|
| 7.3.x   | :white_check_mark: |
| < 7.3   | :x:                |

## Reporting a Vulnerability

**DO NOT open a public GitHub issue for security vulnerabilities.**

To report a security vulnerability in LoomScan:

1. Email the maintainer at **security@loomscan.dev** (or open a private
   security advisory on GitHub: `Security` → `Advisories` → `New advisory`).
2. Include a clear description of the issue, steps to reproduce, and the
   impact assessment.
3. You will receive an acknowledgement within **48 hours**.
4. We will investigate and provide a fix timeline within **7 days**.
5. Once a fix is released, we will publish a security advisory and credit
   the reporter (unless they prefer to remain anonymous).

## Scope

**In scope:**
- Vulnerabilities in LoomScan's own code (rule engine, orchestrator, CLI,
  HTML report generator, installer)
- Supply-chain risks in `loomscan install-tools` (binary download, SHA256
  verification, archive extraction)
- Path traversal / arbitrary code execution via rule packs or scan targets
- XSS / injection in the HTML dashboard
- Secret leakage in scan output (HTML, JSON, SARIF, terminal)

**Out of scope:**
- Vulnerabilities in the projects LoomScan scans (those belong to the
  target project, not LoomScan)
- Vulnerabilities in third-party dependencies (report to upstream)
- Findings produced by LoomScan that are false positives (use GitHub
  issues, not the security channel)
- Denial of service via extremely large scan targets (LoomScan is
  designed for codebases, not adversarial inputs)

## Supply-Chain Security

### Binary Tool Installation (`loomscan install-tools`)

LoomScan downloads pre-built binaries (semgrep, tree-sitter, etc.) from
GitHub releases. As of v7.3.4:

- **SHA256 checksums are mandatory** for every binary tool. If a checksum
  is not pinned for the current platform, the install **REFUSES** to
  proceed.
- Users who need to override this protection can set
  `LOOMSCAN_ALLOW_UNVERIFIED_INSTALL=1` in the environment — this is
  **NOT RECOMMENDED** and produces a warning on stderr.
- Checksums are pinned per-platform in `loomscan/installer.py` via the
  `ToolSpec.checksums` dict. To add a checksum for a new platform,
  compute it with `sha256sum <binary>` after a verified download.

### Python Dependencies

Python dependencies are pinned in `pyproject.toml` with lower-bound
version constraints. We rely on `pip`'s HTTPS transport for integrity.
For production deployments, we recommend using `pip install --require-hashes`
with a pinned `requirements.txt` generated via `pip-compile`.

## Threat Model

LoomScan is a **SAST tool** that reads source code and produces findings.
The trust boundary is:

- **Trusted input**: rule packs (shipped with LoomScan), CLI flags from
  the user, the user's own `.loomscan.yaml` config.
- **Untrusted input**: the codebase being scanned. LoomScan must not
  execute, compile, or import code from the scan target. All analysis is
  static (regex / AST / CPG).
- **Output**: HTML/JSON/SARIF reports. These must not contain XSS or
  injection that would execute when viewed in a browser or CI log.

If you find a way to make LoomScan execute code from the scan target,
that is a critical vulnerability — please report it immediately.

## Disclosure Timeline

- **Day 0**: Reporter privately discloses vulnerability.
- **Day 1**: Maintainer acknowledges and begins investigation.
- **Day 7**: Maintainer provides a fix timeline (or explains why no fix
  is needed).
- **Day 30** (typical): Fix released in a new LoomScan version.
- **Day 37**: Public advisory published (7-day grace period for users
  to upgrade).

For critical vulnerabilities (RCE, supply-chain), the timeline is
compressed to **48 hours** for the fix and **72 hours** for the public
advisory.
