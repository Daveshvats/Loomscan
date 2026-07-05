"""Rule registry — discover and pull rule packs.

A "rule pack" is a curated set of Semgrep or Rego rules. STCA bundles several
packs in stca/rules/packs/, and users can pull additional packs from URLs
into ~/.stca/rules/.
"""
from __future__ import annotations

import urllib.request
from pathlib import Path
from typing import List, Dict


# Built-in rule packs shipped with STCA
BUILTIN_PACKS = {
    # STCA original packs
    "python-security": {
        "path": "packs/python-security.yml",
        "language": "python",
        "rules": 26,
        "description": "OWASP Top 10 + Python-specific antipatterns",
    },
    "python-frameworks": {
        "path": "packs/python-frameworks.yml",
        "language": "python",
        "rules": 35,
        "description": "Django, Flask, FastAPI framework-specific rules",
    },
    "javascript-security": {
        "path": "packs/javascript-security.yml",
        "language": "javascript,typescript",
        "rules": 22,
        "description": "XSS, prototype pollution, SSRF, SQL injection",
    },
    "javascript-frameworks": {
        "path": "packs/javascript-frameworks.yml",
        "language": "javascript,typescript",
        "rules": 33,
        "description": "Express, React, Next.js, NestJS framework-specific rules",
    },
    "go-security": {
        "path": "packs/go-security.yml",
        "language": "go",
        "rules": 12,
        "description": "Crypto, SQL injection, TLS, path traversal",
    },
    "java-security": {
        "path": "packs/java-security.yml",
        "language": "java",
        "rules": 12,
        "description": "Deserialization, XXE, SQL injection",
    },
    "java-frameworks": {
        "path": "packs/java-frameworks.yml",
        "language": "java",
        "rules": 28,
        "description": "Spring, Hibernate, JPA framework-specific rules",
    },
    "cpp-security": {
        "path": "packs/cpp-security.yml",
        "language": "c,cpp",
        "rules": 12,
        "description": "Buffer overflows, format strings, use-after-free",
    },
    # Ported packs from OSS tools
    "detekt-ported": {
        "path": "packs/detekt-ported.yml",
        "language": "python",
        "rules": 25,
        "description": "Ported from detekt (Kotlin): complexity, style, empty-blocks, exceptions, potential-bugs, naming, performance",
    },
    "spotbugs-ported": {
        "path": "packs/spotbugs-ported.yml",
        "language": "python",
        "rules": 20,
        "description": "Ported from SpotBugs (Java): BAD_PRACTICE, CORRECTNESS, MALICIOUS_CODE, MULTI_THREADING, PERFORMANCE, STYLE",
    },
    "lintr-ported": {
        "path": "packs/lintr-ported.yml",
        "language": "python",
        "rules": 22,
        "description": "Ported from lintr (R): assignment, braces, operators, quotes, semicolons, spaces, naming, deprecated",
    },
    "luacheck-ported": {
        "path": "packs/luacheck-ported.yml",
        "language": "python",
        "rules": 16,
        "description": "Ported from luacheck (Lua): globals, read-only, unused, recursion, redefined, shadow, type, format",
    },
    "react-security": {
        "path": "packs/react-security.yml",
        "language": "javascript,typescript",
        "rules": 32,
        "description": "React/JS-specific: localStorage JWT, JSX XSS, AES-ECB, hardcoded keys, test URLs, auth guards, switch/default, fetch without auth, JSON.parse, setInterval, CryptoJS, template literal XSS",
    },
    "no-secrets-in-logs": {
        "path": "../policies/no_secrets_in_logs.rego",
        "language": "rego",
        "rules": 4,
        "description": "Rego policy — no secrets/PII in log/print statements",
    },
}


# Curated external rule packs (free, OSS)
EXTERNAL_PACKS = {
    "semgrep-community": {
        "url": "https://semgrep.dev/r/all",
        "language": "multi",
        "description": "Semgrep community rules — all languages",
    },
    "semgrep-owasp": {
        "url": "https://semgrep.dev/r/owasp-top-25",
        "language": "multi",
        "description": "OWASP Top 25 vulnerability patterns",
    },
    "semgrep-django": {
        "url": "https://semgrep.dev/r/django",
        "language": "python",
        "description": "Django-specific security rules",
    },
    "semgrep-flask": {
        "url": "https://semgrep.dev/r/flask",
        "language": "python",
        "description": "Flask-specific security rules",
    },
    "semgrep-react": {
        "url": "https://semgrep.dev/r/react",
        "language": "javascript,typescript",
        "description": "React-specific security rules",
    },
    "semgrep-express": {
        "url": "https://semgrep.dev/r/expressjs",
        "language": "javascript,typescript",
        "description": "Express.js security rules",
    },
    "semgrep-go": {
        "url": "https://semgrep.dev/r/golang",
        "language": "go",
        "description": "Go security rules",
    },
    "trailofbits": {
        "url": "https://github.com/Traho/semgrep-rules",
        "language": "multi",
        "description": "Trail of Bits security rules",
    },
}


def get_builtin_pack_path(name: str) -> Path:
    """Get the filesystem path to a built-in rule pack."""
    if name not in BUILTIN_PACKS:
        raise ValueError(f"Unknown pack: {name}")
    return Path(__file__).parent / BUILTIN_PACKS[name]["path"]


def list_builtin_packs() -> Dict:
    return BUILTIN_PACKS


def list_external_packs() -> Dict:
    return EXTERNAL_PACKS


def get_all_packs_for_files(files: List[str]) -> List[Path]:
    """Return all built-in rule pack paths applicable to the given files.

    Auto-selects packs based on file extensions.
    """
    from collections import defaultdict
    exts = defaultdict(int)
    for f in files:
        ext = Path(f).suffix.lower()
        exts[ext] += 1

    pack_paths: List[Path] = []
    if any(e in (".py",) for e in exts):
        pack_paths.append(get_builtin_pack_path("python-security"))
        pack_paths.append(get_builtin_pack_path("python-frameworks"))
        # include ported packs from detekt, spotbugs, lintr, luacheck
        pack_paths.append(get_builtin_pack_path("detekt-ported"))
        pack_paths.append(get_builtin_pack_path("spotbugs-ported"))
        pack_paths.append(get_builtin_pack_path("lintr-ported"))
        pack_paths.append(get_builtin_pack_path("luacheck-ported"))
    if any(e in (".js", ".jsx", ".ts", ".tsx") for e in exts):
        pack_paths.append(get_builtin_pack_path("javascript-security"))
        pack_paths.append(get_builtin_pack_path("javascript-frameworks"))
        pack_paths.append(get_builtin_pack_path("react-security"))
    if any(e in (".go",) for e in exts):
        pack_paths.append(get_builtin_pack_path("go-security"))
    if any(e in (".java",) for e in exts):
        pack_paths.append(get_builtin_pack_path("java-security"))
        pack_paths.append(get_builtin_pack_path("java-frameworks"))
    if any(e in (".c", ".cpp", ".cc", ".h", ".hpp") for e in exts):
        pack_paths.append(get_builtin_pack_path("cpp-security"))
    return pack_paths


def pull_external_pack(name: str, dest_dir: Path) -> Path:
    """Download an external rule pack into dest_dir.

    For Semgrep registry URLs (semgrep.dev/r/...), we don't actually download
    the file — semgrep's `--config <url>` handles that. We just record the URL
    in a manifest for the L0 layer to use.
    """
    if name not in EXTERNAL_PACKS:
        raise ValueError(f"Unknown external pack: {name}")
    url = EXTERNAL_PACKS[name]["url"]
    dest_dir.mkdir(parents=True, exist_ok=True)
    manifest = dest_dir / "external-packs.json"
    import json
    data = {}
    if manifest.exists():
        try:
            data = json.loads(manifest.read_text())
        except Exception:
            pass
    data[name] = {"url": url, **EXTERNAL_PACKS[name]}
    manifest.write_text(json.dumps(data, indent=2))
    return manifest
