"""Replace silent `except Exception: pass` patterns in orchestrator.py with
logged warnings. Uses literal string matching on the surrounding context to
identify each scanner by name.

Idempotent — safe to re-run.
"""
from __future__ import annotations
from pathlib import Path

PATH = Path("/home/z/my-project/stca-pipeline/stca/orchestrator.py")
src = PATH.read_text()

# Each tuple: (scanner_name, old_block, new_block)
REPLACEMENTS = [
    (
        "counterfactual.mutation",
        '                            removed_count += 1\n                except Exception:\n                    pass\n',
        '                            removed_count += 1\n                except Exception as e:\n                    _log_scanner_error("counterfactual.mutation", e)\n',
    ),
    (
        "counterfactual.filter",
        '            if removed_count > 0:\n                result.findings = [f for f in result.findings if f.confidence >= 0.3]\n        except Exception:\n            pass\n',
        '            if removed_count > 0:\n                result.findings = [f for f in result.findings if f.confidence >= 0.3]\n        except Exception as e:\n            _log_scanner_error("counterfactual.filter", e, exc_info=True)\n',
    ),
    (
        "issue_store.upsert (full_repo)",
        '                "total_in_store": self.issue_store.stats()["total_issues"],\n            }\n        except Exception:\n            pass\n\n        self._save_reports(result)\n        result.layer_timings["__total__"] = time.perf_counter() - t0\n        return result',
        '                "total_in_store": self.issue_store.stats()["total_issues"],\n            }\n        except Exception as e:\n            _log_scanner_error("issue_store.upsert (full_repo)", e, exc_info=True)\n\n        self._save_reports(result)\n        result.layer_timings["__total__"] = time.perf_counter() - t0\n        return result',
    ),
    (
        "issue_store.upsert (run)",
        '                "total_in_store": self.issue_store.stats()["total_issues"],\n            }\n        except Exception:\n            pass\n\n        # Step 5: aggregate via IT2-FIS',
        '                "total_in_store": self.issue_store.stats()["total_issues"],\n            }\n        except Exception as e:\n            _log_scanner_error("issue_store.upsert (run)", e, exc_info=True)\n\n        # Step 5: aggregate via IT2-FIS',
    ),
    (
        "missing_patches",
        '                    raw={"cve": m.cve, "package": m.package,\n                         "vulnerable_snippet": m.vulnerable_snippet},\n                ))\n        except Exception:\n            pass\n        return findings\n\n    def _run_malicious_pattern_detection',
        '                    raw={"cve": m.cve, "package": m.package,\n                         "vulnerable_snippet": m.vulnerable_snippet},\n                ))\n        except Exception as e:\n            _log_scanner_error("missing_patches", e)\n        return findings\n\n    def _run_malicious_pattern_detection',
    ),
    (
        "malicious_patterns",
        '                        raw={"pattern_type": h.pattern_type, "indicator": h.indicator,\n                             "context": h.context},\n                    ))\n        except Exception:\n            pass\n        return findings\n\n    def _run_flawfinder_scan',
        '                        raw={"pattern_type": h.pattern_type, "indicator": h.indicator,\n                             "context": h.context},\n                    ))\n        except Exception as e:\n            _log_scanner_error("malicious_patterns", e)\n        return findings\n\n    def _run_flawfinder_scan',
    ),
    (
        "flawfinder",
        '                    raw={"function": h.function, "risk_level": h.risk_level,\n                         "context": h.context},\n                ))\n        except Exception:\n            pass\n        return findings\n\n    def _run_contract_verification',
        '                    raw={"function": h.function, "risk_level": h.risk_level,\n                         "context": h.context},\n                ))\n        except Exception as e:\n            _log_scanner_error("flawfinder", e)\n        return findings\n\n    def _run_contract_verification',
    ),
    (
        "contracts",
        '                    raw={"function": v.function, "contract_type": v.contract_type,\n                         "condition": v.condition},\n                ))\n        except Exception:\n            pass\n        return findings\n\n    def _run_pii_detection',
        '                    raw={"function": v.function, "contract_type": v.contract_type,\n                         "condition": v.condition},\n                ))\n        except Exception as e:\n            _log_scanner_error("contracts", e)\n        return findings\n\n    def _run_pii_detection',
    ),
    (
        "pii_detection",
        '                    raw={"pii_type": d.pii_type, "preview": d.value_preview},\n                ))\n        except Exception:\n            pass\n        return findings\n\n    def _run_architecture_check',
        '                    raw={"pii_type": d.pii_type, "preview": d.value_preview},\n                ))\n        except Exception as e:\n            _log_scanner_error("pii_detection", e)\n        return findings\n\n    def _run_architecture_check',
    ),
    (
        "architecture",
        '                    raw={"importing_layer": v.importing_layer,\n                         "imported_layer": v.imported_layer,\n                         "imported_module": v.imported_module},\n                ))\n        except Exception:\n            pass\n        return findings\n\n    def _run_doc_audit',
        '                    raw={"importing_layer": v.importing_layer,\n                         "imported_layer": v.imported_layer,\n                         "imported_module": v.imported_module},\n                ))\n        except Exception as e:\n            _log_scanner_error("architecture", e)\n        return findings\n\n    def _run_doc_audit',
    ),
    (
        "doc_audit",
        '                    raw={"issue_type": issue.issue_type, "name": issue.name},\n                ))\n        except Exception:\n            pass\n        return findings\n\n    def _run_html_config_scan',
        '                    raw={"issue_type": issue.issue_type, "name": issue.name},\n                ))\n        except Exception as e:\n            _log_scanner_error("doc_audit", e)\n        return findings\n\n    def _run_html_config_scan',
    ),
    (
        "html_config",
        '                    raw={"issue_type": issue.issue_type},\n                ))\n        except Exception:\n            pass\n        return findings\n\n    def _run_js_taint_tracking',
        '                    raw={"issue_type": issue.issue_type},\n                ))\n        except Exception as e:\n            _log_scanner_error("html_config", e)\n        return findings\n\n    def _run_js_taint_tracking',
    ),
    (
        "js_taint",
        '                    raw={"source": flow.source, "source_type": flow.source_type,\n                         "sink": flow.sink, "sink_type": flow.sink_type,\n                         "cross_file": flow.cross_file,\n                         "path": flow.path},\n                ))\n        except Exception:\n            pass\n        return findings\n\n    def _run_js_pattern_scan',
        '                    raw={"source": flow.source, "source_type": flow.source_type,\n                         "sink": flow.sink, "sink_type": flow.sink_type,\n                         "cross_file": flow.cross_file,\n                         "path": flow.path},\n                ))\n        except Exception as e:\n            _log_scanner_error("js_taint", e)\n        return findings\n\n    def _run_js_pattern_scan',
    ),
    (
        "js_patterns",
        '                    raw={"context": hit.context, "pattern": hit.rule_id},\n                ))\n        except Exception:\n            pass\n        return findings\n\n    def _quick_recheck',
        '                    raw={"context": hit.context, "pattern": hit.rule_id},\n                ))\n        except Exception as e:\n            _log_scanner_error("js_patterns", e)\n        return findings\n\n    def _quick_recheck',
    ),
    (
        "quick_recheck",
        "            else:\n                # Generic: return empty (can't re-check unknown rule type)\n                pass\n        except Exception:\n            pass\n        return results\n\n    def _run_v2_analyzers",
        "            else:\n                # Generic: return empty (can't re-check unknown rule type)\n                pass\n        except Exception as e:\n            _log_scanner_error(f\"quick_recheck[{rule_id}]\", e)\n        return results\n\n    def _run_v2_analyzers",
    ),
    (
        "incremental.cache_init",
        '        try:\n            from .incremental import FileLevelCache\n            file_cache = FileLevelCache(self.repo_root)\n        except Exception:\n            file_cache = None',
        '        try:\n            from .incremental import FileLevelCache\n            file_cache = FileLevelCache(self.repo_root)\n        except Exception as e:\n            _log_scanner_error("incremental.cache_init", e)\n            file_cache = None',
    ),
    (
        "cpg_queries",
        '                    raw=result.raw or {},\n                ))\n        except Exception:\n            pass\n        return findings\n\n    def _run_metamorphic_tests',
        '                    raw=result.raw or {},\n                ))\n        except Exception as e:\n            _log_scanner_error("cpg_queries", e)\n        return findings\n\n    def _run_metamorphic_tests',
    ),
]

applied = 0
skipped = []
for name, old, new in REPLACEMENTS:
    if old in src:
        src = src.replace(old, new, 1)
        applied += 1
        print(f"  [OK] {name}")
    else:
        skipped.append(name)
        print(f"  [SKIP] {name} -- pattern not found")

PATH.write_text(src)
print(f"\nApplied {applied}/{len(REPLACEMENTS)} replacements.")
if skipped:
    print(f"Skipped: {skipped}")

# Sanity: count remaining silent except: pass at common indentations
import re
remaining = re.findall(r'except Exception:\n\s*pass\n', src)
print(f"\nRemaining silent `except Exception: pass` patterns: {len(remaining)}")
for r in remaining:
    print(f"  - found at index {src.find(r)}")
