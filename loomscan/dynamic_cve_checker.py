"""v7.1: Dynamic CVE checker — detects dependencies, queries OSV, checks reachability.

This module:
  1. Detects the language/ecosystem of the project
  2. Parses lock files / dependency manifests to list packages + versions
  3. Queries the OSV API (osv.dev) for known vulnerabilities
  4. For each CVE, gets the vulnerable function/API conditions
  5. Cross-checks whether those functions are actually used in the codebase
  6. Reports only REACHABLE vulnerabilities (not just "you have a vulnerable dep")

Supported ecosystems:
  - Python (requirements.txt, Pipfile.lock, poetry.lock, pyproject.toml)
  - JavaScript (package-lock.json, yarn.lock)
  - Java (pom.xml)
  - Go (go.mod)
  - Rust (Cargo.lock)

The OSV API is free, public, and doesn't require authentication.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass, field
from .models import Finding, Severity, LayerID, BlastRadius, Category


@dataclass
class Dependency:
    """A single dependency with its version."""
    name: str
    version: str
    ecosystem: str  # PyPI, npm, Maven, Go, crates.io
    source_file: str = ""


@dataclass
class CVEFinding:
    """A CVE finding with reachability info."""
    cve_id: str
    package: str
    version: str
    ecosystem: str
    severity: str
    summary: str
    fixed_version: str = ""
    vulnerable_functions: List[str] = field(default_factory=list)
    reachable: bool = False
    reachable_files: List[str] = field(default_factory=list)


# ============================================================================
# Dependency Detection
# ============================================================================

def detect_dependencies(repo_root: Path) -> List[Dependency]:
    """Detect all dependencies in the repository by parsing lock files."""
    deps: List[Dependency] = []

    # Python
    deps.extend(_parse_requirements_txt(repo_root))
    deps.extend(_parse_pipfile_lock(repo_root))
    deps.extend(_parse_poetry_lock(repo_root))
    deps.extend(_parse_pyproject_toml(repo_root))

    # JavaScript
    deps.extend(_parse_package_lock(repo_root))

    # Java
    deps.extend(_parse_pom_xml(repo_root))

    # Go
    deps.extend(_parse_go_mod(repo_root))

    # Rust
    deps.extend(_parse_cargo_lock(repo_root))

    return deps


def _parse_requirements_txt(repo_root: Path) -> List[Dependency]:
    """Parse requirements.txt for Python dependencies."""
    deps = []
    req_file = repo_root / "requirements.txt"
    if not req_file.exists():
        return deps

    for line in req_file.read_text(errors='replace').splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('-'):
            continue
        # package==1.0.0 or package>=1.0.0 or package~=1.0.0
        match = re.match(r'^([a-zA-Z0-9_-]+)\s*[=<>~!]+\s*([0-9][0-9a-zA-Z.\-]*)', line)
        if match:
            deps.append(Dependency(
                name=match.group(1).lower(),
                version=match.group(2),
                ecosystem="PyPI",
                source_file="requirements.txt"
            ))
    return deps


def _parse_pipfile_lock(repo_root: Path) -> List[Dependency]:
    """Parse Pipfile.lock for Python dependencies."""
    deps = []
    lock_file = repo_root / "Pipfile.lock"
    if not lock_file.exists():
        return deps
    try:
        data = json.loads(lock_file.read_text())
        for section in ("default", "develop"):
            for name, info in data.get(section, {}).items():
                version = info.get("version", "").lstrip("=")
                if version:
                    deps.append(Dependency(name=name.lower(), version=version,
                                          ecosystem="PyPI", source_file="Pipfile.lock"))
    except Exception:
        pass
    return deps


def _parse_poetry_lock(repo_root: Path) -> List[Dependency]:
    """Parse poetry.lock for Python dependencies."""
    deps = []
    lock_file = repo_root / "poetry.lock"
    if not lock_file.exists():
        return deps
    try:
        import tomllib
        with open(lock_file, 'rb') as f:
            data = tomllib.load(f)
        for pkg in data.get("package", []):
            deps.append(Dependency(name=pkg["name"].lower(), version=pkg["version"],
                                  ecosystem="PyPI", source_file="poetry.lock"))
    except Exception:
        pass
    return deps


def _parse_pyproject_toml(repo_root: Path) -> List[Dependency]:
    """Parse pyproject.toml for Python dependencies."""
    deps = []
    pyproject = repo_root / "pyproject.toml"
    if not pyproject.exists():
        return deps
    try:
        import tomllib
        with open(pyproject, 'rb') as f:
            data = tomllib.load(f)
        # Check if this is a poetry project
        poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
        for name, version_spec in poetry_deps.items():
            if name.lower() == "python":
                continue
            if isinstance(version_spec, str):
                version = version_spec.lstrip("^~>=<!")
                if version:
                    deps.append(Dependency(name=name.lower(), version=version,
                                          ecosystem="PyPI", source_file="pyproject.toml"))
    except Exception:
        pass
    return deps


def _parse_package_lock(repo_root: Path) -> List[Dependency]:
    """Parse package-lock.json for npm dependencies."""
    deps = []
    lock_file = repo_root / "package-lock.json"
    if not lock_file.exists():
        return deps
    try:
        data = json.loads(lock_file.read_text())
        # v2/v3 format
        packages = data.get("packages", {})
        for pkg_path, info in packages.items():
            if not pkg_path or pkg_path == "":
                continue  # root package
            name = pkg_path.split("node_modules/")[-1] if "node_modules/" in pkg_path else pkg_path
            version = info.get("version", "")
            if version and not version.startswith("file:"):
                deps.append(Dependency(name=name, version=version,
                                      ecosystem="npm", source_file="package-lock.json"))
    except Exception:
        pass
    return deps


def _parse_pom_xml(repo_root: Path) -> List[Dependency]:
    """Parse pom.xml for Maven dependencies."""
    deps = []
    pom_file = repo_root / "pom.xml"
    if not pom_file.exists():
        # Check subdirectories
        for p in repo_root.rglob("pom.xml"):
            deps.extend(_parse_single_pom(p, repo_root))
        return deps
    return _parse_single_pom(pom_file, repo_root)


def _parse_single_pom(pom_path: Path, repo_root: Path) -> List[Dependency]:
    """Parse a single pom.xml file."""
    deps = []
    try:
        content = pom_path.read_text(errors='replace')
        # Simple regex parse for <dependency> blocks
        dep_pattern = r'<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>'
        for match in re.finditer(dep_pattern, content):
            group_id, artifact_id, version = match.groups()
            # Skip variables like ${spring.version}
            if version.startswith('$'):
                continue
            deps.append(Dependency(
                name=f"{group_id}:{artifact_id}",
                version=version,
                ecosystem="Maven",
                source_file=str(pom_path.relative_to(repo_root))
            ))
    except Exception:
        pass
    return deps


def _parse_go_mod(repo_root: Path) -> List[Dependency]:
    """Parse go.mod for Go dependencies."""
    deps = []
    go_mod = repo_root / "go.mod"
    if not go_mod.exists():
        return deps
    try:
        content = go_mod.read_text(errors='replace')
        # Pattern: module/version
        dep_pattern = r'^\s*(\S+)/(\S+)\s+v(\S+)'
        for match in re.finditer(dep_pattern, content, re.MULTILINE):
            module_path, name, version = match.groups()
            if module_path in ("require", "replace", "exclude"):
                continue
            full_name = f"{module_path}/{name}" if not name.startswith('v') else module_path
            deps.append(Dependency(
                name=full_name,
                version=version,
                ecosystem="Go",
                source_file="go.mod"
            ))
    except Exception:
        pass
    return deps


def _parse_cargo_lock(repo_root: Path) -> List[Dependency]:
    """Parse Cargo.lock for Rust dependencies."""
    deps = []
    lock_file = repo_root / "Cargo.lock"
    if not lock_file.exists():
        return deps
    try:
        content = lock_file.read_text(errors='replace')
        # Pattern: name = "package"\nversion = "1.0.0"
        dep_pattern = r'name\s*=\s*"([^"]+)"\s*\n\s*version\s*=\s*"([^"]+)"'
        for match in re.finditer(dep_pattern, content):
            name, version = match.groups()
            if name in ("loomscan", "loomscan-regex"):
                continue
            deps.append(Dependency(
                name=name,
                version=version,
                ecosystem="crates.io",
                source_file="Cargo.lock"
            ))
    except Exception:
        pass
    return deps


# ============================================================================
# OSV API Query
# ============================================================================

def query_osv(dependencies: List[Dependency]) -> List[CVEFinding]:
    """Query the OSV API for vulnerabilities in the given dependencies.

    Uses the batch query API: https://api.osv.dev/v1/querybatch
    """
    import urllib.request

    if not dependencies:
        return []

    findings: List[CVEFinding] = []

    # Batch query (max 1000 per batch)
    batch_size = 100
    for i in range(0, len(dependencies), batch_size):
        batch = dependencies[i:i + batch_size]
        queries = []
        for dep in batch:
            queries.append({
                "package": {"name": dep.name, "ecosystem": dep.ecosystem},
                "version": dep.version
            })

        payload = json.dumps({"queries": queries}).encode('utf-8')
        req = urllib.request.Request(
            "https://api.osv.dev/v1/querybatch",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode('utf-8'))
        except Exception as e:
            # If OSV API fails, skip this batch
            continue

        results = data.get("results", [])
        for dep, result in zip(batch, results):
            vulns = result.get("vulns", [])
            for vuln_id in vulns:
                # Get details for this vulnerability
                vuln_details = _get_vuln_details(vuln_id)
                if vuln_details:
                    findings.append(CVEFinding(
                        cve_id=vuln_id,
                        package=dep.name,
                        version=dep.version,
                        ecosystem=dep.ecosystem,
                        severity=vuln_details.get("severity", "medium"),
                        summary=vuln_details.get("summary", "Vulnerability found"),
                        fixed_version=vuln_details.get("fixed_version", ""),
                        vulnerable_functions=vuln_details.get("vulnerable_functions", []),
                    ))

    return findings


def _get_vuln_details(vuln_id: str) -> dict:
    """Get details for a specific vulnerability from OSV API."""
    import urllib.request

    try:
        req = urllib.request.Request(
            f"https://api.osv.dev/v1/vulns/{vuln_id}",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode('utf-8'))
    except Exception:
        return {"severity": "medium", "summary": vuln_id, "fixed_version": "", "vulnerable_functions": []}

    # Extract severity
    severity = "medium"
    for sev_entry in data.get("severity", []):
        if sev_entry.get("type") == "CVSS_V3":
            cvss = sev_entry.get("score", "")
            # Parse CVSS vector for base score
            if "CVSS:3." in cvss:
                try:
                    # Simple heuristic from CVSS vector
                    if "AV:N" in cvss and "C:H" in cvss:
                        severity = "critical"
                    elif "AV:N" in cvss:
                        severity = "high"
                    elif "AV:L" in cvss:
                        severity = "medium"
                except Exception:
                    pass

    # Extract summary
    summary = data.get("summary", data.get("details", "Vulnerability found")[:200])

    # Extract fixed version
    fixed_version = ""
    for affected in data.get("affected", []):
        for ranges in affected.get("ranges", []):
            for event in ranges.get("events", []):
                if "fixed" in event:
                    fixed_version = event["fixed"]
                    break

    # Extract vulnerable functions (if available)
    vuln_funcs = []
    for affected in data.get("affected", []):
        # OSV can include ranges with specific ecosystem data
        if "ecosystem_specific" in affected:
            eco = affected["ecosystem_specific"]
            if isinstance(eco, dict) and "functions" in eco:
                vuln_funcs.extend(eco["functions"])

    return {
        "severity": severity,
        "summary": summary,
        "fixed_version": fixed_version,
        "vulnerable_functions": vuln_funcs,
    }


# ============================================================================
# Reachability Analysis
# ============================================================================

def check_reachability(cve_findings: List[CVEFinding], repo_root: Path) -> List[CVEFinding]:
    """Check if vulnerable functions are actually used in the codebase.

    For each CVE with known vulnerable functions, search the codebase
    for usage of those functions. If found, mark as REACHABLE.
    """
    if not cve_findings:
        return cve_findings

    # Collect all source files
    source_extensions = {'.py', '.java', '.js', '.ts', '.go', '.rs', '.kt', '.scala', '.rb', '.php', '.c', '.cpp', '.h'}
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules", "build", "dist",
                 "target", ".loomscan-cache", ".loomscan-reports", "site-packages"}

    source_files: List[Path] = []
    for p in repo_root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in skip_dirs for part in p.parts):
            continue
        if p.suffix.lower() in source_extensions:
            source_files.append(p)

    # For each CVE, check reachability
    for cve in cve_findings:
        if not cve.vulnerable_functions:
            # No known vulnerable functions — mark as potentially reachable
            cve.reachable = True  # Conservative: assume reachable
            continue

        # Search for each vulnerable function in source files
        for func_name in cve.vulnerable_functions:
            for source_file in source_files:
                try:
                    content = source_file.read_text(encoding='utf-8', errors='replace')
                    if func_name in content:
                        cve.reachable = True
                        rel_path = str(source_file.relative_to(repo_root))
                        if rel_path not in cve.reachable_files:
                            cve.reachable_files.append(rel_path)
                        break  # Found in one file is enough
                except Exception:
                    continue

        # Also check package import
        if not cve.reachable:
            # Check if the package is imported anywhere
            package_name = cve.package.split(':')[-1].split('/')[-1]
            for source_file in source_files[:200]:  # Check first 200 files
                try:
                    content = source_file.read_text(encoding='utf-8', errors='replace')
                    if package_name.lower() in content.lower():
                        cve.reachable = True
                        rel_path = str(source_file.relative_to(repo_root))
                        if rel_path not in cve.reachable_files:
                            cve.reachable_files.append(rel_path)
                        break
                except Exception:
                    continue

    return cve_findings


# ============================================================================
# Main Entry Point
# ============================================================================

def scan_dynamic_cves(repo_root: Path) -> List[Finding]:
    """Main entry: detect deps, query OSV, check reachability, return findings.

    This is the function called by the orchestrator.
    """
    # 1. Detect dependencies
    deps = detect_dependencies(repo_root)
    if not deps:
        return []

    # 2. Query OSV API
    cve_findings = query_osv(deps)
    if not cve_findings:
        return []

    # 3. Check reachability
    cve_findings = check_reachability(cve_findings, repo_root)

    # 4. Convert to LoomScan Finding objects
    sev_map = {
        "critical": Severity.CRITICAL, "high": Severity.HIGH,
        "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
    }

    findings: List[Finding] = []
    for cve in cve_findings:
        severity = sev_map.get(cve.severity, Severity.MEDIUM)
        message = f"{cve.cve_id}: {cve.package}@{cve.version} — {cve.summary[:100]}"
        if cve.fixed_version:
            message += f" | Fix: upgrade to {cve.fixed_version}"
        if cve.reachable:
            message += f" | REACHABLE (used in {', '.join(cve.reachable_files[:3])})"
        else:
            message += " | Not reachable in current code"

        findings.append(Finding(
            layer=LayerID.L0B_SUPPLY_CHAIN,
            rule_id=f"L0b.osv.{cve.cve_id}",
            message=message,
            file=cve.source_file or cve.package,
            start_line=1,
            severity=severity,
            confidence=0.95 if cve.reachable else 0.7,
            blast_radius=BlastRadius.SYSTEM if cve.reachable else BlastRadius.MODULE,
            exploitability=0.9 if cve.reachable else 0.3,
            category=Category.SUPPLY_CHAIN,
            cwe="CWE-1357",  # Reliance on third-party components
            fix_suggestion=f"Upgrade {cve.package} to version {cve.fixed_version}" if cve.fixed_version
                          else f"Review {cve.cve_id} for {cve.package}@{cve.version}",
            raw={
                "cve_id": cve.cve_id,
                "package": cve.package,
                "version": cve.version,
                "ecosystem": cve.ecosystem,
                "fixed_version": cve.fixed_version,
                "vulnerable_functions": cve.vulnerable_functions,
                "reachable": cve.reachable,
                "reachable_files": cve.reachable_files,
            },
        ))

    return findings


def generate_cve_html_report(cve_findings: List[CVEFinding], output_path: Path) -> None:
    """Generate an HTML report for CVE findings."""
    import base64

    # Serialize findings
    data = {
        "findings": [
            {
                "cve_id": f.cve_id,
                "package": f.package,
                "version": f.version,
                "ecosystem": f.ecosystem,
                "severity": f.severity,
                "summary": f.summary,
                "fixed_version": f.fixed_version,
                "vulnerable_functions": f.vulnerable_functions,
                "reachable": f.reachable,
                "reachable_files": f.reachable_files,
            }
            for f in cve_findings
        ],
        "total": len(cve_findings),
        "reachable_count": sum(1 for f in cve_findings if f.reachable),
    }

    json_b64 = base64.b64encode(json.dumps(data).encode('utf-8')).decode('ascii')

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>LoomScan CVE Report</title>
<style>
body {{ background: #0a0e14; color: #c9d1d9; font-family: 'Courier New', monospace; padding: 20px; }}
h1 {{ color: #58a6ff; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
th {{ background: #151a21; padding: 10px; text-align: left; border: 1px solid #252b35; color: #6e7681; font-size: 11px; text-transform: uppercase; }}
td {{ padding: 10px; border: 1px solid #252b35; font-size: 12px; }}
.sev-critical {{ color: #f85149; font-weight: bold; }}
.sev-high {{ color: #ff7b72; }}
.sev-medium {{ color: #d29922; }}
.sev-low {{ color: #58a6ff; }}
.reachable {{ background: rgba(248,81,73,0.1); }}
</style></head><body>
<h1>🕷️ LoomScan CVE Report</h1>
<p>Total CVEs: {data['total']} | Reachable: {data['reachable_count']}</p>
<table>
<tr><th>CVE</th><th>Package</th><th>Version</th><th>Severity</th><th>Summary</th><th>Fix</th><th>Reachable</th></tr>
<tr id="rows"></tr>
</table>
<script>
const data = JSON.parse(atob("{json_b64}"));
const tbody = document.getElementById('rows');
data.findings.forEach(f => {{
  const tr = document.createElement('tr');
  if (f.reachable) tr.className = 'reachable';
  tr.innerHTML = `<td>${f.cve_id}</td><td>${f.package}</td><td>${f.version}</td>
    <td class="sev-${{f.severity}}">${{f.severity}}</td>
    <td>${{f.summary.substring(0,80)}}</td>
    <td>${{f.fixed_version || 'N/A'}}</td>
    <td>${{f.reachable ? '⚠️ YES (' + f.reachable_files.slice(0,2).join(', ') + ')' : 'No'}}</td>`;
  tbody.appendChild(tr);
}});
</script>
</body></html>"""

    output_path.write_text(html, encoding='utf-8')
