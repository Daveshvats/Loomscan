"""Replace silent `except Exception: pass` patterns across the stca package.

Strategy:
- Add a module-level `logger = logging.getLogger("stca.<module>")` to each file
  that doesn't already have one.
- Replace each silent `except: pass` with a logged call. The log level depends
  on the call site's role:
    * "warning" — file I/O, JSON parsing, scanner calls (failures lose data)
    * "debug"   — optional language parsers, optional tool invocation
                  (failure is acceptable; just slows down the scan)
- For per-file iteration loops, use logger.debug to avoid log spam.
- Idempotent: safe to re-run.

Each replacement is anchored on a unique snippet of surrounding context to
avoid accidental matches.
"""
from __future__ import annotations
import re
from pathlib import Path

ROOT = Path("/home/z/my-project/stca-pipeline/stca")

# (file_relative_to_stca, list_of_replacements)
# Each replacement is (old, new, level) where level is "warning" or "debug".
# Anchors must be unique within their file.

FIXES: dict[str, list[tuple[str, str, str]]] = {
    "baseline.py": [
        (
            '            for e_dict in data.get("entries", []):\n                entry = BaselineEntry(**e_dict)\n                self.entries[entry.fingerprint] = entry\n        except Exception:\n            pass\n',
            '            for e_dict in data.get("entries", []):\n                entry = BaselineEntry(**e_dict)\n                self.entries[entry.fingerprint] = entry\n        except Exception as e:\n            logger.warning("Failed to load baseline file %s: %s", self.baseline_file, e)\n',
            "warning",
        ),
    ],
    "brain/aggregator.py": [
        (
            '                    bugs_missed=s.get("fn", 0),\n                )\n        except Exception:\n            pass\n',
            '                    bugs_missed=s.get("fn", 0),\n                )\n        except Exception as e:\n            logger.warning("Failed to load layer reliability stats: %s", e)\n',
            "warning",
        ),
    ],
    "brain/project_tuner.py": [
        (
            '            self.store_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")\n        except Exception:\n            pass\n',
            '            self.store_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")\n        except Exception as e:\n            logger.warning("Failed to save project tuner feedback: %s", e)\n',
            "warning",
        ),
    ],
    "cli.py": [
        # SBOM package.json
        (
            '                    "purl": f"pkg:npm/{name}@{ver_clean}",\n                    })\n        except Exception:\n            pass\n\n    # Go\n    go_mod = repo_root / "go.mod"',
            '                    "purl": f"pkg:npm/{name}@{ver_clean}",\n                    })\n        except Exception as e:\n            logger.warning("Failed to parse package.json for SBOM: %s", e)\n\n    # Go\n    go_mod = repo_root / "go.mod"',
            "warning",
        ),
        # SBOM go.mod
        (
            '                            "purl": f"pkg:golang/{parts[0]}@{parts[1]}",\n                        })\n        except Exception:\n            pass\n\n    # Rust\n    cargo_lock = repo_root / "Cargo.lock"',
            '                            "purl": f"pkg:golang/{parts[0]}@{parts[1]}",\n                        })\n        except Exception as e:\n            logger.warning("Failed to parse go.mod for SBOM: %s", e)\n\n    # Rust\n    cargo_lock = repo_root / "Cargo.lock"',
            "warning",
        ),
        # SBOM Cargo.lock
        (
            '                    "purl": f"pkg:cargo/{current_pkg}@{current_ver}",\n                })\n        except Exception:\n            pass\n\n    if fmt == "cyclonedx":',
            '                    "purl": f"pkg:cargo/{current_pkg}@{current_ver}",\n                })\n        except Exception as e:\n            logger.warning("Failed to parse Cargo.lock for SBOM: %s", e)\n\n    if fmt == "cyclonedx":',
            "warning",
        ),
    ],
    "deadcode.py": [
        # _load
        (
            '                    self.functions[func_id].called = True\n                    self.functions[func_id].call_count = data.get("counts", {}).get(func_id, 1)\n        except Exception:\n            pass\n',
            '                    self.functions[func_id].called = True\n                    self.functions[func_id].call_count = data.get("counts", {}).get(func_id, 1)\n        except Exception as e:\n            logger.warning("Failed to load dead-code trace file %s: %s", self.trace_file, e)\n',
            "warning",
        ),
        # tracing instrumentation snippet (cannot add logger — code is a string template)
        # Skip this one — it's a code template for instrumenting user code,
        # so it has no access to our logger.
    ],
    "diff_slicer.py": [
        # 6 sites: optional tree-sitter language parsers. Use debug-level
        # because failures here are common (language not installed).
        (
            '    try:\n        parsers["python"] = Parser(Language(tspython.language()))\n    except Exception:\n        pass\n',
            '    try:\n        parsers["python"] = Parser(Language(tspython.language()))\n    except Exception as e:\n        logger.debug("tree-sitter python parser unavailable: %s", e)\n',
            "debug",
        ),
        (
            '    try:\n        parsers["javascript"] = Parser(Language(tsjs.language()))\n    except Exception:\n        pass\n',
            '    try:\n        parsers["javascript"] = Parser(Language(tsjs.language()))\n    except Exception as e:\n        logger.debug("tree-sitter javascript parser unavailable: %s", e)\n',
            "debug",
        ),
        (
            '        try:\n            parsers["go"] = Parser(Language(tsgo.language()))\n        except Exception:\n            pass\n',
            '        try:\n            parsers["go"] = Parser(Language(tsgo.language()))\n        except Exception as e:\n            logger.debug("tree-sitter go parser unavailable: %s", e)\n',
            "debug",
        ),
        (
            '        try:\n            parsers["java"] = Parser(Language(tsjava.language()))\n        except Exception:\n            pass\n',
            '        try:\n            parsers["java"] = Parser(Language(tsjava.language()))\n        except Exception as e:\n            logger.debug("tree-sitter java parser unavailable: %s", e)\n',
            "debug",
        ),
        (
            '        try:\n            parsers["c"] = Parser(Language(tsc.language()))\n        except Exception:\n            pass\n',
            '        try:\n            parsers["c"] = Parser(Language(tsc.language()))\n        except Exception as e:\n            logger.debug("tree-sitter c parser unavailable: %s", e)\n',
            "debug",
        ),
        (
            '        try:\n            parsers["cpp"] = Parser(Language(tscpp.language()))\n        except Exception:\n            pass\n',
            '        try:\n            parsers["cpp"] = Parser(Language(tscpp.language()))\n        except Exception as e:\n            logger.debug("tree-sitter cpp parser unavailable: %s", e)\n',
            "debug",
        ),
    ],
    "feedback/stats.py": [
        (
            '                    bugs_missed=s.get("fn", 0),\n                )\n        except Exception:\n            pass\n',
            '                    bugs_missed=s.get("fn", 0),\n                )\n        except Exception as e:\n            logger.warning("Failed to load feedback stats: %s", e)\n',
            "warning",
        ),
    ],
    "hotspots.py": [
        (
            '            for h_dict in data.get("hotspots", []):\n                h = Hotspot(**h_dict)\n                self.hotspots[h.id] = h\n        except Exception:\n            pass\n',
            '            for h_dict in data.get("hotspots", []):\n                h = Hotspot(**h_dict)\n                self.hotspots[h.id] = h\n        except Exception as e:\n            logger.warning("Failed to load hotspots file %s: %s", self.hotspots_file, e)\n',
            "warning",
        ),
    ],
    "incremental.py": [
        # Only the _save site — the _load site falls back to empty index {}.
        (
            '    def _save(self) -> None:\n        try:\n            self.index_file.write_text(json.dumps(self.index, indent=2), encoding="utf-8")\n        except Exception:\n            pass\n',
            '    def _save(self) -> None:\n        try:\n            self.index_file.write_text(json.dumps(self.index, indent=2), encoding="utf-8")\n        except Exception as e:\n            logger.warning("Failed to save incremental cache %s: %s", self.index_file, e)\n',
            "warning",
        ),
    ],
    "installer.py": [
        (
            '    if VERSIONS_FILE.exists():\n        try:\n            data = json.loads(VERSIONS_FILE.read_text())\n        except Exception:\n            pass\n',
            '    if VERSIONS_FILE.exists():\n        try:\n            data = json.loads(VERSIONS_FILE.read_text())\n        except Exception as e:\n            logger.warning("Failed to read versions file %s: %s", VERSIONS_FILE, e)\n',
            "warning",
        ),
    ],
    "interprocedural.py": [
        # per-file discovery loop (line 226)
        (
            '            try:\n                all_sources += discover_sources_in_file(p, repo_root)\n            except Exception:\n                pass\n            count += 1',
            '            try:\n                all_sources += discover_sources_in_file(p, repo_root)\n            except Exception as e:\n                logger.debug("source discovery failed on %s: %s", p.name, e)\n            count += 1',
            "debug",
        ),
        # per-file analysis loop (line 1045)
        (
            '            try:\n                flows += self._analyze_file(p, repo_root)\n            except Exception:\n                pass\n\n            count += 1',
            '            try:\n                flows += self._analyze_file(p, repo_root)\n            except Exception as e:\n                logger.debug("interprocedural analysis failed on %s: %s", p.name, e)\n\n            count += 1',
            "debug",
        ),
    ],
    "js_cpg.py": [
        (
            '                for pattern in JS_SANITIZERS:\n                    if re.search(pattern, line):\n                        return True\n        except Exception:\n            pass\n        return False\n',
            '                for pattern in JS_SANITIZERS:\n                    if re.search(pattern, line):\n                        return True\n        except Exception as e:\n            logger.debug("sanitizer check failed: %s", e)\n        return False\n',
            "debug",
        ),
    ],
    "layers/l0_fast.py": [
        (
            '                try:\n                    data = json.loads(external_manifest.read_text())\n                    configs.extend(p["url"] for p in data.values())\n                except Exception:\n                    pass\n',
            '                try:\n                    data = json.loads(external_manifest.read_text())\n                    configs.extend(p["url"] for p in data.values())\n                except Exception as e:\n                    logger.warning("Failed to load external packs manifest %s: %s", external_manifest, e)\n',
            "warning",
        ),
    ],
    "layers/l0b_supply_chain.py": [
        # _audit_npm
        (
            '                    fix_suggestion=f"Run `npm audit fix` to update {vuln_id}",\n                    raw=vuln,\n                ))\n        except Exception:\n            pass\n        return findings\n\n    def _audit_go',
            '                    fix_suggestion=f"Run `npm audit fix` to update {vuln_id}",\n                    raw=vuln,\n                ))\n        except Exception as e:\n            logger.warning("npm audit failed: %s", e)\n        return findings\n\n    def _audit_go',
            "warning",
        ),
        # _audit_go
        (
            '                            raw=obj,\n                        ))\n                except json.JSONDecodeError:\n                    continue\n        except Exception:\n            pass\n        return findings\n\n    def _audit_rust',
            '                            raw=obj,\n                        ))\n                except json.JSONDecodeError:\n                    continue\n        except Exception as e:\n            logger.warning("go vuln audit failed: %s", e)\n        return findings\n\n    def _audit_rust',
            "warning",
        ),
        # _audit_rust
        (
            '                    fix_suggestion=f"Update {vuln.get(\'package\', {}).get(\'name\')} to patched version",\n                    raw=vuln,\n                ))\n        except Exception:\n            pass\n        return findings\n\n    def _audit_osv',
            '                    fix_suggestion=f"Update {vuln.get(\'package\', {}).get(\'name\')} to patched version",\n                    raw=vuln,\n                ))\n        except Exception as e:\n            logger.warning("rust cargo audit failed: %s", e)\n        return findings\n\n    def _audit_osv',
            "warning",
        ),
        # _audit_osv
        (
            '                            fix_suggestion=f"Update {pkg.get(\'package\', {}).get(\'name\')} to a fixed version",\n                            raw=vuln,\n                        ))\n        except Exception:\n            pass\n        return findings\n\n    def _check_eol_versions',
            '                            fix_suggestion=f"Update {pkg.get(\'package\', {}).get(\'name\')} to a fixed version",\n                            raw=vuln,\n                        ))\n        except Exception as e:\n            logger.warning("OSV.dev audit failed: %s", e)\n        return findings\n\n    def _check_eol_versions',
            "warning",
        ),
        # typosquat check
        (
            '                                fix_suggestion=f"Replace \'{dep}\' with \'{TYPOSQUATS[dep]}\'",\n                            ))\n            except Exception:\n                pass\n\n        return findings',
            '                                fix_suggestion=f"Replace \'{dep}\' with \'{TYPOSQUATS[dep]}\'",\n                            ))\n            except Exception as e:\n                logger.warning("typosquat check failed: %s", e)\n\n        return findings',
            "warning",
        ),
    ],
    "layers/l0c_dependencies.py": [
        # _check_deprecated_packages
        (
            '                                fix_suggestion=f"Replace \'{dep}\' with {DEPRECATED_PACKAGES[dep]}",\n                            ))\n            except Exception:\n                pass\n        return findings\n\n    def _check_outdated_python',
            '                                fix_suggestion=f"Replace \'{dep}\' with {DEPRECATED_PACKAGES[dep]}",\n                            ))\n            except Exception as e:\n                logger.warning("deprecated package check failed: %s", e)\n        return findings\n\n    def _check_outdated_python',
            "warning",
        ),
        # _check_outdated_python
        (
            '                    fix_suggestion=f"pip install --upgrade {pkg[\'name\']}",\n                    raw=pkg,\n                ))\n        except Exception:\n            pass\n        return findings\n\n    def _check_outdated_node',
            '                    fix_suggestion=f"pip install --upgrade {pkg[\'name\']}",\n                    raw=pkg,\n                ))\n        except Exception as e:\n            logger.warning("outdated python package check failed: %s", e)\n        return findings\n\n    def _check_outdated_node',
            "warning",
        ),
        # _check_outdated_node
        (
            '                    fix_suggestion=f"npm install {name}@latest",\n                    raw=info,\n                ))\n        except Exception:\n            pass\n        return findings\n\n    def _check_licenses',
            '                    fix_suggestion=f"npm install {name}@latest",\n                    raw=info,\n                ))\n        except Exception as e:\n            logger.warning("outdated node package check failed: %s", e)\n        return findings\n\n    def _check_licenses',
            "warning",
        ),
        # _check_licenses
        (
            '                            fix_suggestion=f"Replace {pkg[\'Name\']} with a permissive-licensed alternative",\n                            raw=pkg,\n                        ))\n                        break\n        except Exception:\n            pass\n        return findings',
            '                            fix_suggestion=f"Replace {pkg[\'Name\']} with a permissive-licensed alternative",\n                            raw=pkg,\n                        ))\n                        break\n        except Exception as e:\n            logger.warning("license check failed: %s", e)\n        return findings',
            "warning",
        ),
    ],
    "layers/l7_simulation.py": [
        (
            '                                raw={"line": line},\n                            ))\n            except Exception:\n                pass\n\n        return findings\n',
            '                                raw={"line": line},\n                            ))\n            except Exception as e:\n                logger.warning("simulation layer scanner failed: %s", e)\n\n        return findings\n',
            "warning",
        ),
    ],
    "layers/l8_autofix.py": [
        # _gofmt_fix (external tool, debug level)
        (
            '            if proc.returncode == 0:\n                return path.read_text(encoding="utf-8")\n        except Exception:\n            pass\n        return None\n\n    def _ruff_fix',
            '            if proc.returncode == 0:\n                return path.read_text(encoding="utf-8")\n        except Exception as e:\n            logger.debug("gofmt autofix failed on %s: %s", path, e)\n        return None\n\n    def _ruff_fix',
            "debug",
        ),
        # _ruff_fix (external tool, debug level)
        (
            '            if proc.returncode == 0:\n                return path.read_text(encoding="utf-8")\n        except Exception:\n            pass\n        return None\n\n    def _apply_patch',
            '            if proc.returncode == 0:\n                return path.read_text(encoding="utf-8")\n        except Exception as e:\n            logger.debug("ruff autofix failed on %s: %s", path, e)\n        return None\n\n    def _apply_patch',
            "debug",
        ),
        # _apply_patch (file write, warning level)
        (
            '    def _apply_patch(self, file_path: Path, new_content: str) -> None:\n        """Apply a patch (full file replacement) to disk."""\n        try:\n            file_path.write_text(new_content, encoding="utf-8")\n        except Exception:\n            pass\n',
            '    def _apply_patch(self, file_path: Path, new_content: str) -> None:\n        """Apply a patch (full file replacement) to disk."""\n        try:\n            file_path.write_text(new_content, encoding="utf-8")\n        except Exception as e:\n            logger.warning("Failed to apply autofix patch to %s: %s", file_path, e)\n',
            "warning",
        ),
    ],
    "learning.py": [
        # save
        (
            '    def save(self, path: Path) -> None:\n        try:\n            path.write_text(json.dumps(self.vectors), encoding="utf-8")\n        except Exception:\n            pass\n',
            '    def save(self, path: Path) -> None:\n        try:\n            path.write_text(json.dumps(self.vectors), encoding="utf-8")\n        except Exception as e:\n            logger.warning("Failed to save learning vectors to %s: %s", path, e)\n',
            "warning",
        ),
        # load (line 83 — need to check the load method too)
        (
            '    def load(self, path: Path) -> None:\n        try:\n            self.vectors = json.loads(path.read_text(encoding="utf-8"))\n        except Exception:\n            pass\n',
            '    def load(self, path: Path) -> None:\n        try:\n            self.vectors = json.loads(path.read_text(encoding="utf-8"))\n        except Exception as e:\n            logger.warning("Failed to load learning vectors from %s: %s", path, e)\n',
            "warning",
        ),
    ],
    "multi_lang.py": [
        # Optional import — use debug level (it's expected to fail in some envs)
        (
            'try:\n    from .extra_rules import merge_patterns, EXTRA_CRYPTO, EXTRA_AUTH, EXTRA_MODERN, EXTRA_IDOR\n    CRYPTO_PATTERNS = merge_patterns(CRYPTO_PATTERNS, EXTRA_CRYPTO)\n    AUTH_PATTERNS = merge_patterns(AUTH_PATTERNS, EXTRA_AUTH)\n    MODERN_ATTACK_PATTERNS = merge_patterns(MODERN_ATTACK_PATTERNS, EXTRA_MODERN)\n    IDOR_PATTERNS = merge_patterns(IDOR_PATTERNS, EXTRA_IDOR)\nexcept Exception:\n    pass\n',
            'try:\n    from .extra_rules import merge_patterns, EXTRA_CRYPTO, EXTRA_AUTH, EXTRA_MODERN, EXTRA_IDOR\n    CRYPTO_PATTERNS = merge_patterns(CRYPTO_PATTERNS, EXTRA_CRYPTO)\n    AUTH_PATTERNS = merge_patterns(AUTH_PATTERNS, EXTRA_AUTH)\n    MODERN_ATTACK_PATTERNS = merge_patterns(MODERN_ATTACK_PATTERNS, EXTRA_MODERN)\n    IDOR_PATTERNS = merge_patterns(IDOR_PATTERNS, EXTRA_IDOR)\nexcept Exception as e:\n    logger.debug("extra_rules module unavailable: %s", e)\n',
            "debug",
        ),
    ],
    "precision.py": [
        # FP learner _load
        (
            '            for p_dict in data.get("patterns", []):\n                key = f"{p_dict[\'rule_id\']}|{p_dict[\'file_pattern\']}"\n                self.patterns[key] = FPPattern(**p_dict)\n        except Exception:\n            pass\n',
            '            for p_dict in data.get("patterns", []):\n                key = f"{p_dict[\'rule_id\']}|{p_dict[\'file_pattern\']}"\n                self.patterns[key] = FPPattern(**p_dict)\n        except Exception as e:\n            logger.warning("Failed to load FP patterns from %s: %s", self.fp_file, e)\n',
            "warning",
        ),
        # Calibrator _load
        (
            '                for b in self.bins:\n                    if abs(b.lower - b_dict["lower"]) < 0.001:\n                        b.total = b_dict.get("total", 0)\n                        b.correct = b_dict.get("correct", 0)\n                        break\n        except Exception:\n            pass\n',
            '                for b in self.bins:\n                    if abs(b.lower - b_dict["lower"]) < 0.001:\n                        b.total = b_dict.get("total", 0)\n                        b.correct = b_dict.get("correct", 0)\n                        break\n        except Exception as e:\n            logger.warning("Failed to load calibrator bins from %s: %s", self.cal_file, e)\n',
            "warning",
        ),
    ],
    "profiles.py": [
        (
            '            raw = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}\n            for name, data in (raw.get("profiles") or {}).items():\n                self.profiles[name] = Profile.from_dict(name, data)\n        except Exception:\n            pass\n',
            '            raw = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}\n            for name, data in (raw.get("profiles") or {}).items():\n                self.profiles[name] = Profile.from_dict(name, data)\n        except Exception as e:\n            logger.warning("Failed to load custom profiles from %s: %s", self.config_path, e)\n',
            "warning",
        ),
    ],
    "report/dashboard.py": [
        (
            '                    "cwe": mf.cwe, "layer": "L0"})\n        except Exception:\n            pass\n',
            '                    "cwe": mf.cwe, "layer": "L0"})\n        except Exception as e:\n            logger.warning("modern attack scan failed for dashboard: %s", e)\n',
            "warning",
        ),
    ],
    "rule_config.py": [
        (
            '                    note=rule_data.get("note", ""),\n                )\n        except Exception:\n            pass\n',
            '                    note=rule_data.get("note", ""),\n                )\n        except Exception as e:\n            logger.warning("Failed to load rule config: %s", e)\n',
            "warning",
        ),
    ],
    "rules/__init__.py": [
        (
            '    if manifest.exists():\n        try:\n            data = json.loads(manifest.read_text())\n        except Exception:\n            pass\n',
            '    if manifest.exists():\n        try:\n            data = json.loads(manifest.read_text())\n        except Exception as e:\n            logger.warning("Failed to read external packs manifest %s: %s", manifest, e)\n',
            "warning",
        ),
    ],
    "unified_cve_db.py": [
        # seed CVE fallback in get_cves
        (
            '                    self._store_cached(ecosystem, package, version, results)\n                    return results\n            except Exception:\n                pass\n\n        # Step 3: Query OSV.dev',
            '                    self._store_cached(ecosystem, package, version, results)\n                    return results\n            except Exception as e:\n                logger.debug("seed CVE DB lookup failed for %s/%s@%s: %s", ecosystem, package, version, e)\n\n        # Step 3: Query OSV.dev',
            "debug",
        ),
        # seed CVE fallback in batch_get_cves
        (
            '                            self._store_cached(eco, pkg, ver, seed_results)\n                            results.extend(seed_results)\n                            continue\n                    except Exception:\n                        pass\n                uncached.append((i, eco, pkg, ver))',
            '                            self._store_cached(eco, pkg, ver, seed_results)\n                            results.extend(seed_results)\n                            continue\n                    except Exception as e:\n                        logger.debug("seed CVE DB batch lookup failed for %s/%s@%s: %s", eco, pkg, ver, e)\n                uncached.append((i, eco, pkg, ver))',
            "debug",
        ),
    ],
}

# Files that need a module-level logger added.
# We only add one if the file doesn't already have `import logging` or
# `logger = logging.getLogger(...)`.
LOGGER_TEMPLATE = (
    'import logging\n\n'
    'logger = logging.getLogger("stca.{module}")\n\n'
)

# Insert logger AFTER the module docstring + __future__ import.
# We try a few common anchors.
def insert_logger(src: str, module_name: str) -> tuple[str, bool]:
    """Insert a module-level logger if missing. Returns (new_src, inserted)."""
    if "logging.getLogger" in src:
        return src, False
    # Find insertion point: after module docstring + from __future__
    lines = src.splitlines(keepends=True)
    insert_idx = 0
    # Skip leading docstring
    if lines and lines[0].lstrip().startswith('"""'):
        # find closing """
        for i in range(1, len(lines)):
            if '"""' in lines[i]:
                insert_idx = i + 1
                break
    # Skip from __future__ import
    for i in range(insert_idx, len(lines)):
        stripped = lines[i].strip()
        if stripped.startswith("from __future__"):
            insert_idx = i + 1
        elif stripped == "" or stripped.startswith("#"):
            continue
        else:
            break
    # Skip blank lines after
    while insert_idx < len(lines) and lines[insert_idx].strip() == "":
        insert_idx += 1
    logger_block = LOGGER_TEMPLATE.format(module=module_name)
    new_lines = lines[:insert_idx] + [logger_block] + lines[insert_idx:]
    return "".join(new_lines), True


total_applied = 0
total_skipped = 0
total_loggers_added = 0

for rel_path, replacements in FIXES.items():
    py = ROOT / rel_path
    if not py.exists():
        print(f"  [MISS] {rel_path} — file not found")
        continue
    src = py.read_text()
    module_name = rel_path.replace("/", ".").removesuffix(".py")

    # Add logger first if needed
    src, added = insert_logger(src, module_name)
    if added:
        total_loggers_added += 1

    applied_here = 0
    skipped_here = []
    for old, new, level in replacements:
        if old in src:
            src = src.replace(old, new, 1)
            applied_here += 1
        else:
            skipped_here.append(old[:60].replace("\n", "\\n") + "...")
    if applied_here or added:
        py.write_text(src)
    print(f"  {rel_path}: {applied_here}/{len(replacements)} applied, "
          f"logger_added={added}, skipped={len(skipped_here)}")
    for s in skipped_here:
        print(f"    SKIP: {s}")
    total_applied += applied_here
    total_skipped += len(skipped_here)

print()
print(f"=== TOTAL ===")
print(f"Replacements applied: {total_applied}")
print(f"Replacements skipped: {total_skipped}")
print(f"Loggers added: {total_loggers_added}")

# Re-survey to find remaining patterns
print()
print(f"=== Remaining silent except:pass patterns ===")
PATTERN = re.compile(r'except\s+(\w+\s*(?:\([^)]*\))?\s*)?:\n(\s+)pass\b', re.MULTILINE)
remaining = 0
for py in sorted(ROOT.rglob("*.py")):
    src = py.read_text()
    matches = list(PATTERN.finditer(src))
    if not matches:
        continue
    rel = py.relative_to(ROOT.parent)
    lines = [src[:m.start()].count("\n") + 1 for m in matches]
    print(f"  {rel}: {lines}")
    remaining += len(matches)
print(f"\nTotal remaining: {remaining}")
