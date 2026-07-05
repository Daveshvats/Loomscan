"""The orchestrator — runs layers in parallel, aggregates via IT2-FIS,
optionally invokes the LLM tie-breaker, produces a PipelineResult.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional, List
import time
import json

from .config import STCAConfig, find_config
from .diff_slicer import slice_diff
from .models import (
    PipelineResult, Finding, AggregatedDecision, Decision, LayerID, DiffHunk,
    Severity, BlastRadius,
)
from .layers import ALL_LAYERS
from .layers.l0b_supply_chain import L0bSupplyChain
from .layers.l0c_dependencies import L0cDependencies
from .layers.l0d_behavioral import L0dBehavioral
from .layers.l0e_iac import L0eIaC
from .layers.l0f_commit_risk import L0fCommitRisk
from .layers.l8_autofix import L8AutoFix
from .brain.aggregator import Aggregator
from .llm.client import LLMClient
from .llm.prm import PRMScorer
from .feedback.stats import StatsTracker
from .cache import ResultCache
from .suppressions import filter_suppressed
from .taint_cross_file import track_taint_for_files, track_taint_cross_file
from .cpg import build_cpg_for_repo
from .cpg_queries import (query_unsanitized_taint_flows, query_unused_variables,
                           query_dangerous_patterns_in_auth, query_function_complexity)
from .typestate import analyze_typestate
from .metamorphic import run_metamorphic_tests
from .differential import run_differential_tests
from .hotspots import HotspotManager
from .pysa_integration import PysaIntegration, get_pysa_findings_or_fallback
from .advanced_secrets import detect_secrets_advanced
from .coverage import find_coverage_report, track_coverage_history, CoverageReport
from .audit import AuditLogger
from .precision import (apply_precision_pipeline, FPLearner, ConfidenceCalibrator,
                         apply_corroboration)
from .bug_seeds import boost_finding_confidence, cross_reference_finding
from .baseline import Baseline
from .strictness import get_level, filter_findings_by_strictness, should_block
from .nullness import NullnessAnalyzer
from .issue_store import IssueStore
from .consistency import check_all_consistencies
from .models import Category
from .missing_patches import scan_missing_patches
from .contracts import extract_all_contracts, check_preconditions_at_call_sites
from .flawfinder_db import scan_repo_dangerous_functions
from .malicious_patterns import scan_repo_malicious_patterns
from .pii_detection import scan_repo_pii
from .root_cause import find_root_causes, rca_stats
from .impact_analysis import ImpactAnalyzer
from .architecture import ArchitectureEnforcer
from .doc_audit import audit_repo
from .html_scanner import scan_html_config
from .js_cpg import JavaScriptCPG, scan_js_taint_flows
from .js_pattern_scanner import scan_repo_js_patterns


class Orchestrator:
    """Runs the full pipeline on a git diff."""

    def __init__(self, repo_root: Path, config: Optional[STCAConfig] = None,
                 strictness: int = None, use_baseline: bool = False):
        self.repo_root = repo_root
        self.config = config or STCAConfig.from_file(find_config(repo_root))
        self.stats_path = repo_root / self.config.stats_file
        self.aggregator = Aggregator(self.stats_path)
        self.cache = ResultCache(repo_root)
        self.hotspots = HotspotManager(repo_root)
        self.audit = AuditLogger(repo_root)
        self.fp_learner = FPLearner(repo_root)
        self.calibrator = ConfidenceCalibrator(repo_root)
        self.baseline = Baseline(repo_root)
        self.issue_store = IssueStore(repo_root)
        self.nullness = NullnessAnalyzer()
        # strictness level (from CLI or config)
        self.strictness = strictness or self.config.layers.get("__strictness__", {}).get("level", 5)
        self.use_baseline = use_baseline
        self.llm: Optional[LLMClient] = None
        self.prm = PRMScorer()
        if self.config.llm.get("enabled"):
            self.llm = LLMClient(
                endpoint=self.config.llm.get("endpoint", "http://localhost:11434"),
                model=self.config.llm.get("model", "qwen3-coder-1.5b"),
            )

    def run_full(self) -> PipelineResult:
        """Run the pipeline on ALL source files (not just diff).

        This is the full-repo scan mode. It discovers all source files and
        treats them as "changed" so every layer runs on every file.
        """
        self.audit.log("check_run", {"mode": "full"})

        result = PipelineResult()
        t0 = time.perf_counter()

        # Discover ALL source files and create synthetic diff hunks
        skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                     ".stca-cache", ".stca-reports", ".stca-fixes", "build",
                     "dist", ".pytest_cache", "coverage"}
        source_extensions = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java",
                             ".c", ".cpp", ".cc", ".h", ".hpp", ".hxx",
                             ".tf", ".yaml", ".yml", ".json", ".env",
                             ".dockerfile", ".sh", ".cfg", ".ini", ".conf"}

        all_hunks: List[DiffHunk] = []
        for p in self.repo_root.rglob("*"):
            if not p.is_file():
                continue
            if any(part in skip_dirs for part in p.parts):
                continue
            if p.suffix.lower() in source_extensions or p.name.lower().startswith("dockerfile"):
                rel = str(p.relative_to(self.repo_root))
                all_hunks.append(DiffHunk(
                    file=rel, start_line=1, end_line=9999,
                    added_lines=[], removed_lines=[],
                ))

        result.diff_hunks = all_hunks

        if not all_hunks:
            return result

        # Run the same layer pipeline as run(), but with all files
        enabled_layers = []
        for layer_cls in ALL_LAYERS:
            layer_cfg = self.config.layers.get(layer_cls.id.value)
            if layer_cfg and layer_cfg.enabled:
                if layer_cls.id in (LayerID.L6_SYMBOLIC, LayerID.L7_SIMULATION):
                    if not any(self.config.is_critical_path(h.file) for h in all_hunks) and \
                       not any(self.config.is_concurrency_path(h.file) for h in all_hunks):
                        continue
                enabled_layers.append(layer_cls())

        enabled_layers.append(L0bSupplyChain())
        enabled_layers.append(L0cDependencies())
        enabled_layers.append(L0dBehavioral())
        if any(self._is_iac_file(h.file) for h in all_hunks) or self._has_any_iac_files():
            enabled_layers.append(L0eIaC())
        enabled_layers.append(L0fCommitRisk())

        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_layer = {
                executor.submit(self._run_layer_cached, layer, all_hunks): layer
                for layer in enabled_layers
            }
            for future in as_completed(future_to_layer):
                layer = future_to_layer[future]
                try:
                    findings, elapsed = future.result()
                except Exception as e:
                    findings = [Finding(
                        layer=getattr(layer, 'id', LayerID.L0_FAST),
                        rule_id=f"{layer.name}.internal_error",
                        message=f"Layer crashed: {type(e).__name__}: {e}",
                        file="<pipeline>", start_line=0,
                    )]
                    elapsed = 0.0
                result.findings.extend(findings)
                result.layer_timings[layer.name] = elapsed
                result.layers_run.append(layer.name)

        # Dedupe
        seen = set()
        unique_findings: List[Finding] = []
        for f in result.findings:
            if f.fingerprint not in seen:
                seen.add(f.fingerprint)
                unique_findings.append(f)
        result.findings = unique_findings

        # Advanced detection
        result.findings += self._run_cross_file_taint_tracking_with_pysa(all_hunks)
        result.findings += self._run_advanced_secret_detection(all_hunks)
        result.findings += self._run_hotspot_detection(all_hunks)
        result.findings += self._run_typestate_analysis(all_hunks)
        result.findings += self._run_cpg_queries(all_hunks)
        result.findings += self._run_metamorphic_tests(all_hunks)
        result.findings += self._run_differential_tests(all_hunks)
        result.findings += self._run_coverage_checks(all_hunks)
        result.findings += self._run_nullness_analysis(all_hunks)
        result.findings += self._run_consistency_checks()
        result.findings += self._run_missing_patch_detection()
        result.findings += self._run_malicious_pattern_detection(all_hunks)
        result.findings += self._run_flawfinder_scan()
        result.findings += self._run_contract_verification(all_hunks)
        result.findings += self._run_pii_detection(all_hunks)
        result.findings += self._run_architecture_check()
        result.findings += self._run_doc_audit()
        result.findings += self._run_html_config_scan()
        result.findings += self._run_js_taint_tracking()
        result.findings += self._run_js_pattern_scan()

        # v2 analyzers (multi-lang, code quality, config, IaC, supply chain, AST)
        result.findings += self._run_v2_analyzers()

        # Suppression filter
        kept, suppressed = filter_suppressed(result.findings, self.repo_root)
        result.findings = kept
        result.suppressed_count = len(suppressed)

        # Bug-seed boost
        for f in result.findings:
            new_conf, seed_name = boost_finding_confidence(f)
            if seed_name:
                f.confidence = new_conf
                if not f.raw:
                    f.raw = {}
                f.raw["bug_seed"] = seed_name

        # Precision pipeline
        result.findings, precision_stats = apply_precision_pipeline(
            result.findings, self.repo_root, self.fp_learner, self.calibrator
        )
        result.precision_stats = precision_stats

        # Strictness filter
        result.findings = filter_findings_by_strictness(result.findings, self.strictness)

        # FIS aggregation
        result.decisions, result.final_decision = self.aggregator.aggregate(result.findings)

        # Auto-fix
        fixable_findings = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        if fixable_findings:
            autofix = L8AutoFix(apply=False)
            fix_findings = autofix.run(self.repo_root, all_hunks, self.config,
                                        prior_findings=fixable_findings)
            result.findings.extend(fix_findings)

        # Store in issue store
        try:
            new_count, recurring_count = self.issue_store.upsert_findings(result.findings)
            result.issue_store_stats = {
                "new": new_count, "recurring": recurring_count,
                "total_in_store": self.issue_store.stats()["total_issues"],
            }
        except Exception:
            pass

        self._save_reports(result)
        result.layer_timings["__total__"] = time.perf_counter() - t0
        return result

    def run(self, base: str = "HEAD", staged: bool = False) -> PipelineResult:

        result = PipelineResult()
        t0 = time.perf_counter()

        # Step 1: slice the diff
        result.diff_hunks = slice_diff(self.repo_root, base=base, staged=staged)
        if not result.diff_hunks:
            # clean diff — still run supply chain checks (they're diff-independent)
            enabled_layers = [L0bSupplyChain(), L0cDependencies()]
            for layer in enabled_layers:
                findings, elapsed = layer.time_run(self.repo_root, [], self.config)
                result.findings.extend(findings)
                result.layer_timings[layer.name] = elapsed
                result.layers_run.append(layer.name)
            result.decisions, result.final_decision = self.aggregator.aggregate(result.findings)
            self._save_reports(result)
            return result

        # Step 2: instantiate enabled layers
        enabled_layers = []
        for layer_cls in ALL_LAYERS:
            layer_cfg = self.config.layers.get(layer_cls.id.value)
            if layer_cfg and layer_cfg.enabled:
                # force-enable L6 for critical paths, L7 for concurrency paths
                if layer_cls.id in (LayerID.L6_SYMBOLIC, LayerID.L7_SIMULATION):
                    if not any(self.config.is_critical_path(h.file) for h in result.diff_hunks) and \
                       not any(self.config.is_concurrency_path(h.file) for h in result.diff_hunks):
                        continue
                enabled_layers.append(layer_cls())

        # Always include L0b (supply chain) and L0c (dependency health) — they're fast
        enabled_layers.append(L0bSupplyChain())
        enabled_layers.append(L0cDependencies())
        # Behavioral analysis (hotspots, complexity) — fast
        enabled_layers.append(L0dBehavioral())
        # IaC scanning — only if IaC files present
        if any(self._is_iac_file(h.file) for h in result.diff_hunks) or \
           self._has_any_iac_files():
            enabled_layers.append(L0eIaC())
        # Commit risk — always (very fast)
        enabled_layers.append(L0fCommitRisk())

        # Step 3: run layers in parallel (with caching)
        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_layer = {
                executor.submit(self._run_layer_cached, layer, result.diff_hunks): layer
                for layer in enabled_layers
            }
            for future in as_completed(future_to_layer):
                layer = future_to_layer[future]
                try:
                    findings, elapsed = future.result()
                except Exception as e:
                    findings = [Finding(
                        layer=getattr(layer, 'id', LayerID.L0_FAST),
                        rule_id=f"{layer.name}.internal_error",
                        message=f"Layer crashed: {type(e).__name__}: {e}",
                        file="<pipeline>", start_line=0,
                    )]
                    elapsed = 0.0
                result.findings.extend(findings)
                result.layer_timings[layer.name] = elapsed
                result.layers_run.append(layer.name)

        # Step 4: dedupe findings by fingerprint
        seen = set()
        unique_findings: List[Finding] = []
        for f in result.findings:
            if f.fingerprint not in seen:
                seen.add(f.fingerprint)
                unique_findings.append(f)
        result.findings = unique_findings

        # Step 4b: add cross-file taint tracking (CPG-based, with Pysa fallback)
        result.findings += self._run_cross_file_taint_tracking_with_pysa(result.diff_hunks)

        # Step 4b2: advanced secret detection (TruffleHog + entropy)
        result.findings += self._run_advanced_secret_detection(result.diff_hunks)

        # Step 4b3: security hotspot detection (SonarQube-style, with review workflow)
        result.findings += self._run_hotspot_detection(result.diff_hunks)

        # Step 4c: add typestate analysis (state machine violations)
        result.findings += self._run_typestate_analysis(result.diff_hunks)

        # Step 4d: add CPG queries (Joern-style pattern queries)
        result.findings += self._run_cpg_queries(result.diff_hunks)

        # Step 4e: add metamorphic testing (oracle-free bug detection)
        if self.config.layers.get("L1_property") and \
           self.config.layers["L1_property"].enabled:
            result.findings += self._run_metamorphic_tests(result.diff_hunks)

        # Step 4f: add differential testing (refactor verification)
        result.findings += self._run_differential_tests(result.diff_hunks)

        # Step 4g: coverage integration (track coverage drops on changed files)
        result.findings += self._run_coverage_checks(result.diff_hunks)

        # Step 4h: filter suppressed findings (inline `# stca: ignore`)
        kept, suppressed = filter_suppressed(result.findings, self.repo_root)
        result.findings = kept
        result.suppressed_count = len(suppressed)

        # Step 4i: bug-seed cross-reference — boost confidence for known CWE patterns
        for f in result.findings:
            new_conf, seed_name = boost_finding_confidence(f)
            if seed_name:
                f.confidence = new_conf
                if not f.raw:
                    f.raw = {}
                f.raw["bug_seed"] = seed_name

        # Step 4j: precision pipeline — corroboration + FP learning + calibration
        result.findings, precision_stats = apply_precision_pipeline(
            result.findings, self.repo_root, self.fp_learner, self.calibrator
        )
        result.precision_stats = precision_stats

        # Step 4k: nullness analysis (NilAway-inspired) — None dereference detection
        result.findings += self._run_nullness_analysis(result.diff_hunks)

        # Step 4l: consistency checker (credo-inspired) — inconsistent patterns
        result.findings += self._run_consistency_checks()

        # Step 4k2: missing-patch detection (Vanir-inspired) — unpatched CVEs
        result.findings += self._run_missing_patch_detection()

        # Step 4k3: malicious package pattern detection (aura-inspired)
        result.findings += self._run_malicious_pattern_detection(result.diff_hunks)

        # Step 4k4: C/C++ dangerous function database (flawfinder-inspired)
        result.findings += self._run_flawfinder_scan()

        # Step 4l2: contract verification (deal-inspired) — check @pre/@post
        result.findings += self._run_contract_verification(result.diff_hunks)

        # Step 4l3: PII detection (pii-shield-inspired)
        result.findings += self._run_pii_detection(result.diff_hunks)

        # Step 4l4: architecture enforcement (rev-dep-inspired)
        result.findings += self._run_architecture_check()

        # Step 4l5: documentation audit (valknut-inspired)
        result.findings += self._run_doc_audit()

        # Step 4m: strictness filtering (PHPStan-inspired) — only report at configured level
        result.findings = filter_findings_by_strictness(result.findings, self.strictness)

        # Step 4n: baseline filtering (detekt-inspired) — only flag NEW issues
        if self.use_baseline and self.baseline.exists():
            result.findings, baselined = self.baseline.filter_new(result.findings)
            result.baselined_count = len(baselined)

        # Step 4o: store findings in issue store (CodeChecker-inspired) + trend tracking
        try:
            new_count, recurring_count = self.issue_store.upsert_findings(result.findings)
            result.issue_store_stats = {
                "new": new_count, "recurring": recurring_count,
                "total_in_store": self.issue_store.stats()["total_issues"],
            }
        except Exception:
            pass

        # Step 5: aggregate via IT2-FIS
        result.decisions, result.final_decision = self.aggregator.aggregate(result.findings)

        # Step 6: optional LLM tie-breaker for UNCERTAIN findings
        if self.llm and self.config.llm.get("only_on_uncertain", True):
            for i, (finding, decision) in enumerate(zip(result.findings, result.decisions)):
                if decision.decision == Decision.UNCERTAIN:
                    llm_decision = self._llm_tie_break(finding)
                    if llm_decision:
                        result.decisions[i] = llm_decision
                        result.llm_invoked = True
            # recompute final decision
            from .models import Decision as D
            priority = {D.BLOCK: 4, D.WARN: 3, D.UNCERTAIN: 2, D.PASS: 1}
            if result.decisions:
                result.final_decision = max(
                    result.decisions, key=lambda d: priority[d.decision]
                ).decision

        # Step 6b: auto-fix — generate patches for HIGH/CRITICAL findings
        fixable_findings = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        if fixable_findings:
            autofix = L8AutoFix(apply=False)
            fix_findings = autofix.run(self.repo_root, result.diff_hunks, self.config,
                                        prior_findings=fixable_findings)
            result.findings.extend(fix_findings)

        # Step 7: persist reports
        self._save_reports(result)

        result.layer_timings["__total__"] = time.perf_counter() - t0
        return result

    def _run_layer_cached(self, layer, hunks: List[DiffHunk]) -> tuple:
        """Run a layer with function-level result caching."""
        import time as _time
        t0 = _time.perf_counter()

        cached_findings: List[Finding] = []
        uncached_hunks: List[DiffHunk] = []

        for hunk in hunks:
            if hunk.function_body:
                cached = self.cache.get(layer.name, hunk.function_body)
                if cached is not None:
                    for f_dict in cached:
                        try:
                            cached_findings.append(Finding(
                                layer=LayerID(f_dict["layer"]) if f_dict["layer"] in [l.value for l in LayerID] else LayerID.L0_FAST,
                                rule_id=f_dict["rule_id"],
                                message=f_dict["message"],
                                file=f_dict["file"],
                                start_line=f_dict["start_line"],
                                end_line=f_dict.get("end_line", 0),
                                severity=Severity(f_dict["severity"]),
                                confidence=f_dict["confidence"],
                                blast_radius=BlastRadius(f_dict["blast_radius"]),
                                exploitability=f_dict["exploitability"],
                                cwe=f_dict.get("cwe"),
                                fix_suggestion=f_dict.get("fix_suggestion"),
                                raw=f_dict.get("raw", {}),
                            ))
                        except Exception:
                            continue
                    continue
            uncached_hunks.append(hunk)

        if uncached_hunks or not cached_findings:
            new_findings, _ = layer.time_run(self.repo_root, hunks if not cached_findings else uncached_hunks, self.config)
        else:
            new_findings = []

        cacheable_layers = {"Fast Hooks", "Property Tests", "Invariant Checks", "Policy Checks"}
        if layer.name in cacheable_layers:
            for hunk in uncached_hunks:
                if hunk.function_body:
                    func_findings = [f for f in new_findings if f.file == hunk.file
                                     and hunk.start_line <= f.start_line <= hunk.end_line]
                    self.cache.put(layer.name, hunk.function_body,
                                   [f.to_dict() for f in func_findings])

        elapsed = _time.perf_counter() - t0
        return cached_findings + new_findings, elapsed

    def _run_nullness_analysis(self, hunks: List[DiffHunk]) -> List[Finding]:
        """Run sound nullness analysis (NilAway-inspired) on changed Python files."""
        findings: List[Finding] = []
        seen_files: set = set()
        for hunk in hunks:
            if not hunk.file.endswith(".py") or hunk.file in seen_files:
                continue
            seen_files.add(hunk.file)
            file_path = self.repo_root / hunk.file
            if not file_path.exists():
                continue
            issues = self.nullness.analyze_file(file_path, self.repo_root)
            for issue in issues:
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id="L0.nullness.dereference",
                    message=f"Possible None dereference: {issue.reason}",
                    file=issue.file, start_line=issue.line,
                    severity=Severity.HIGH, confidence=issue.confidence,
                    blast_radius=BlastRadius.FUNCTION, exploitability=0.2,
                    category=Category.RELIABILITY,
                    cwe="CWE-476",  # NULL Pointer Dereference
                    fix_suggestion=f"Add a None check before using '{issue.variable}': `if {issue.variable} is not None: ...`",
                    raw={"variable": issue.variable, "reason": issue.reason,
                         "context": issue.context},
                ))
        return findings

    def _run_consistency_checks(self) -> List[Finding]:
        """Run consistency checks (credo-inspired) across the codebase."""
        findings: List[Finding] = []
        inconsistencies = check_all_consistencies(self.repo_root, max_files=50)
        for inc in inconsistencies:
            findings.append(Finding(
                layer=LayerID.L0_FAST,
                rule_id=f"L0.consistency.{inc.category}",
                message=f"Inconsistency ({inc.category}): {inc.description}",
                file="<codebase>", start_line=0,
                severity=Severity.LOW, confidence=0.7,
                blast_radius=BlastRadius.MODULE, exploitability=0.0,
                category=Category.STYLE,
                fix_suggestion=inc.recommendation,
                raw={"pattern_a": inc.pattern_a, "pattern_b": inc.pattern_b,
                     "files_a": inc.files_using_a[:5], "files_b": inc.files_using_b[:5]},
            ))
        return findings

    def _run_missing_patch_detection(self) -> List[Finding]:
        """Run missing-patch detection (Vanir-inspired)."""
        findings: List[Finding] = []
        try:
            missing = scan_missing_patches(self.repo_root, max_files=100)
            for m in missing:
                sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                           "medium": Severity.MEDIUM, "low": Severity.LOW}
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id=f"L0.missing_patch.{m.cve}",
                    message=f"Missing security patch {m.cve} ({m.package}): {m.description}",
                    file=m.file, start_line=m.line,
                    severity=sev_map.get(m.severity, Severity.MEDIUM),
                    confidence=0.9,
                    blast_radius=BlastRadius.SYSTEM, exploitability=0.8,
                    category=Category.SECURITY,
                    cwe=m.cve,
                    fix_suggestion=f"Update {m.package} — see {m.fix_url}",
                    raw={"cve": m.cve, "package": m.package,
                         "vulnerable_snippet": m.vulnerable_snippet},
                ))
        except Exception:
            pass
        return findings

    def _run_malicious_pattern_detection(self, hunks: List[DiffHunk]) -> List[Finding]:
        """Run malicious package pattern detection (aura-inspired)."""
        findings: List[Finding] = []
        try:
            # scan changed Python files + setup.py
            files_to_scan: List[Path] = []
            for hunk in hunks:
                if hunk.file.endswith(".py"):
                    files_to_scan.append(self.repo_root / hunk.file)
            # always scan setup.py if it exists
            setup_py = self.repo_root / "setup.py"
            if setup_py.exists():
                files_to_scan.append(setup_py)

            for f in files_to_scan:
                if not f.exists():
                    continue
                hits = scan_malicious_patterns(f, self.repo_root)
                for h in hits:
                    sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                               "medium": Severity.MEDIUM, "low": Severity.LOW}
                    findings.append(Finding(
                        layer=LayerID.L0_FAST,
                        rule_id=f"L0.malicious.{h.pattern_type}",
                        message=f"Malicious pattern ({h.pattern_type}): {h.description} — {h.indicator}",
                        file=h.file, start_line=h.line,
                        severity=sev_map.get(h.severity, Severity.HIGH),
                        confidence=0.85,
                        blast_radius=BlastRadius.SYSTEM, exploitability=0.9,
                        category=Category.SECURITY,
                        cwe="CWE-506",  # embedded malicious code
                        fix_suggestion="Investigate this pattern — may indicate a malicious dependency",
                        raw={"pattern_type": h.pattern_type, "indicator": h.indicator,
                             "context": h.context},
                    ))
        except Exception:
            pass
        return findings

    def _run_flawfinder_scan(self) -> List[Finding]:
        """Run C/C++ dangerous function scan (flawfinder-inspired)."""
        findings: List[Finding] = []
        try:
            hits = scan_repo_dangerous_functions(self.repo_root, max_files=100)
            for h in hits:
                # map risk level 1-5 to severity
                sev_map = {5: Severity.CRITICAL, 4: Severity.HIGH,
                           3: Severity.MEDIUM, 2: Severity.LOW, 1: Severity.INFO}
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id=f"L0.flawfinder.{h.function}",
                    message=f"Dangerous function {h.function}() [risk {h.risk_level}/5]: {h.explanation}",
                    file=h.file, start_line=h.line,
                    severity=sev_map.get(h.risk_level, Severity.MEDIUM),
                    confidence=0.95,  # flawfinder is very precise (exact function match)
                    blast_radius=BlastRadius.MODULE,
                    exploitability=0.8 if h.risk_level >= 4 else 0.5,
                    category=Category.SECURITY,
                    cwe=h.cwe,
                    fix_suggestion=h.safer_alternative,
                    raw={"function": h.function, "risk_level": h.risk_level,
                         "context": h.context},
                ))
        except Exception:
            pass
        return findings

    def _run_contract_verification(self, hunks: List[DiffHunk]) -> List[Finding]:
        """Run design-by-contract verification (deal-inspired)."""
        findings: List[Finding] = []
        try:
            contracts = extract_all_contracts(self.repo_root, max_files=50)
            if not contracts:
                return findings
            violations = check_preconditions_at_call_sites(contracts, self.repo_root)
            for v in violations:
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id=f"L0.contract.{v.violation_type}",
                    message=f"Contract violation: {v.message} — {v.function}() called at {v.caller_file}:{v.caller_line} violates {v.contract_type}: {v.condition}",
                    file=v.caller_file or v.file, start_line=v.caller_line or v.line,
                    severity=Severity.HIGH, confidence=0.8,
                    blast_radius=BlastRadius.FUNCTION, exploitability=0.3,
                    category=Category.CORRECTNESS,
                    cwe="CWE-699",
                    fix_suggestion=f"Ensure the precondition is satisfied: {v.condition}",
                    raw={"function": v.function, "contract_type": v.contract_type,
                         "condition": v.condition},
                ))
        except Exception:
            pass
        return findings

    def _run_pii_detection(self, hunks: List[DiffHunk]) -> List[Finding]:
        """Run PII detection (pii-shield-inspired)."""
        findings: List[Finding] = []
        try:
            # scan changed files + all config files
            files_to_scan: List[Path] = []
            for hunk in hunks:
                file_path = self.repo_root / hunk.file
                if file_path.exists():
                    files_to_scan.append(file_path)
            # also scan common PII-containing files
            for pattern in ["**/*.csv", "**/*.json", "**/*.yaml", "**/*.yml", "**/*.txt", "**/*.env"]:
                for p in self.repo_root.glob(pattern)[:10]:
                    if p not in files_to_scan:
                        files_to_scan.append(p)

            for f in files_to_scan[:50]:
                detections = scan_pii(f, self.repo_root)
                for d in detections:
                    sev_map = {0.9: Severity.CRITICAL, 0.8: Severity.HIGH,
                               0.5: Severity.MEDIUM, 0.3: Severity.LOW}
                    sev = Severity.CRITICAL if d.confidence >= 0.85 else \
                          Severity.HIGH if d.confidence >= 0.7 else \
                          Severity.MEDIUM if d.confidence >= 0.4 else Severity.LOW
                    findings.append(Finding(
                        layer=LayerID.L0_FAST,
                        rule_id=f"L0.pii.{d.pii_type}",
                        message=f"PII detected ({d.pii_type}): {d.value_preview} — {d.context[:80]}",
                        file=d.file, start_line=d.line,
                        severity=sev, confidence=d.confidence,
                        blast_radius=BlastRadius.SYSTEM, exploitability=0.5,
                        category=Category.SECURITY,
                        cwe="CWE-359",  # exposure of private personal information
                        fix_suggestion="Remove PII from source code; store in secure data store with access controls",
                        raw={"pii_type": d.pii_type, "preview": d.value_preview},
                    ))
        except Exception:
            pass
        return findings

    def _run_architecture_check(self) -> List[Finding]:
        """Run architecture enforcement (rev-dep-inspired)."""
        findings: List[Finding] = []
        try:
            enforcer = ArchitectureEnforcer(self.repo_root)
            violations = enforcer.check_repo(max_files=50)
            for v in violations:
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id=f"L0.architecture.{v.violation}",
                    message=f"Architecture violation: {v.description}",
                    file=v.file, start_line=v.line,
                    severity=Severity.MEDIUM, confidence=0.7,
                    blast_radius=BlastRadius.MODULE, exploitability=0.0,
                    category=Category.MAINTAINABILITY,
                    cwe="CWE-1058",
                    fix_suggestion=f"Move the import to respect layer boundaries: {v.importing_layer} should not import from {v.imported_layer}",
                    raw={"importing_layer": v.importing_layer,
                         "imported_layer": v.imported_layer,
                         "imported_module": v.imported_module},
                ))
        except Exception:
            pass
        return findings

    def _run_doc_audit(self) -> List[Finding]:
        """Run documentation audit (valknut-inspired)."""
        findings: List[Finding] = []
        try:
            issues = audit_repo(self.repo_root, max_files=50)
            for issue in issues:
                sev_map = {"medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id=f"L0.doc_audit.{issue.issue_type}",
                    message=f"Doc audit: {issue.description}",
                    file=issue.file, start_line=issue.line,
                    severity=sev_map.get(issue.severity, Severity.INFO),
                    confidence=0.9,
                    blast_radius=BlastRadius.FUNCTION, exploitability=0.0,
                    category=Category.MAINTAINABILITY,
                    fix_suggestion="Add or update documentation",
                    raw={"issue_type": issue.issue_type, "name": issue.name},
                ))
        except Exception:
            pass
        return findings

    def _run_html_config_scan(self) -> List[Finding]:
        """Run HTML/config security scan (CSP, security headers, .env secrets)."""
        findings: List[Finding] = []
        try:
            issues = scan_html_config(self.repo_root)
            for issue in issues:
                sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                           "medium": Severity.MEDIUM, "low": Severity.LOW}
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id=f"L0.html_scan.{issue.issue_type}",
                    message=f"HTML/config: {issue.description}",
                    file=issue.file, start_line=issue.line,
                    severity=sev_map.get(issue.severity, Severity.MEDIUM),
                    confidence=0.9,
                    blast_radius=BlastRadius.SYSTEM, exploitability=0.6,
                    category=Category.SECURITY,
                    cwe="CWE-693",
                    fix_suggestion=issue.fix,
                    raw={"issue_type": issue.issue_type},
                ))
        except Exception:
            pass
        return findings

    def _run_js_taint_tracking(self) -> List[Finding]:
        """Run JavaScript CPG taint tracking (cross-file XSS/injection)."""
        findings: List[Finding] = []
        try:
            flows = scan_js_taint_flows(self.repo_root, max_files=300)
            for flow in flows:
                sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                           "medium": Severity.MEDIUM}
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id=f"L0.js_taint.{flow.sink_type}",
                    message=f"JS taint flow: {flow.source_type} → {flow.sink_type} ({'cross-file' if flow.cross_file else 'same-file'}) — {flow.source} reaches {flow.sink} (CWE {flow.cwe})",
                    file=flow.sink_file, start_line=flow.sink_line,
                    severity=sev_map.get(flow.severity, Severity.HIGH),
                    confidence=0.8,
                    blast_radius=BlastRadius.SYSTEM if flow.cross_file else BlastRadius.MODULE,
                    exploitability=0.85,
                    category=Category.SECURITY,
                    cwe=flow.cwe,
                    fix_suggestion=f"Sanitize {flow.source} before passing to {flow.sink}. Use DOMPurify.sanitize() or escapeHtml().",
                    raw={"source": flow.source, "source_type": flow.source_type,
                         "sink": flow.sink, "sink_type": flow.sink_type,
                         "cross_file": flow.cross_file,
                         "path": flow.path},
                ))
        except Exception:
            pass
        return findings

    def _run_js_pattern_scan(self) -> List[Finding]:
        """Run dedicated JS pattern scanner (bypasses semgrep JSX limitations)."""
        findings: List[Finding] = []
        try:
            hits = scan_repo_js_patterns(self.repo_root, max_files=500)
            for hit in hits:
                sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                           "medium": Severity.MEDIUM, "low": Severity.LOW,
                           "info": Severity.INFO, "warning": Severity.MEDIUM}
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id=hit.rule_id,
                    message=hit.message,
                    file=hit.file, start_line=hit.line,
                    severity=sev_map.get(hit.severity, Severity.MEDIUM),
                    confidence=0.9,  # high confidence — exact pattern match
                    blast_radius=BlastRadius.MODULE, exploitability=0.7,
                    category=Category.SECURITY,
                    cwe=hit.cwe,
                    fix_suggestion=hit.fix,
                    raw={"context": hit.context, "pattern": hit.rule_id},
                ))
        except Exception:
            pass
        return findings

    def _run_v2_analyzers(self) -> List[Finding]:
        """Run all v2 analyzers: multi-lang patterns, code quality, config, IaC, supply chain."""
        findings: List[Finding] = []
        sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                   "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}

        # 1. Multi-language pattern scanners
        try:
            from .multi_lang import (scan_crypto_multi, scan_concurrency_multi, scan_auth_multi,
                                       scan_modern_multi, scan_idor_multi, scan_state_machine_multi, scan_repo_multi)
            for scanner, prefix in [(scan_crypto_multi,"crypto"),(scan_concurrency_multi,"concurrency"),
                                     (scan_auth_multi,"auth"),(scan_modern_multi,"modern"),
                                     (scan_idor_multi,"idor"),(scan_state_machine_multi,"state")]:
                try:
                    for lf in scan_repo_multi(self.repo_root, scanner, max_files=400):
                        findings.append(Finding(layer=LayerID.L0_FAST, rule_id=f"L0.{prefix}.{lf.rule_id}",
                            message=lf.description, file=lf.file, start_line=lf.line,
                            severity=sev_map.get(lf.severity, Severity.MEDIUM), confidence=lf.confidence,
                            blast_radius=BlastRadius.SYSTEM, exploitability=0.8, category=Category.SECURITY,
                            cwe=lf.cwe, fix_suggestion=lf.fix))
                except Exception: pass
        except Exception: pass
        # 2. Code quality
        try:
            from .code_quality import analyze_repo_code_quality
            cq_cat = {"maintainability":Category.MAINTAINABILITY,"performance":Category.PERFORMANCE,
                      "correctness":Category.CORRECTNESS,"ux":Category.MAINTAINABILITY,
                      "concurrency":Category.CONCURRENCY,"security":Category.SECURITY}
            for issue in analyze_repo_code_quality(self.repo_root, max_files=400):
                findings.append(Finding(layer=LayerID.L0_FAST, rule_id=f"L0.cq.{issue.rule_id}",
                    message=issue.description, file=issue.file, start_line=issue.line,
                    severity=sev_map.get(issue.severity, Severity.LOW), confidence=issue.confidence,
                    blast_radius=BlastRadius.FUNCTION if issue.category=="maintainability" else BlastRadius.MODULE,
                    exploitability=0.3 if issue.category=="maintainability" else 0.5,
                    category=cq_cat.get(issue.category, Category.MAINTAINABILITY), cwe=issue.cwe, fix_suggestion=issue.fix))
        except Exception: pass
        # 3. Config scanner
        try:
            from .config_scanner import scan_repo_configs
            for issue in scan_repo_configs(self.repo_root, max_files=50):
                findings.append(Finding(layer=LayerID.L0_FAST, rule_id=issue.rule_id,
                    message=issue.description, file=issue.file, start_line=issue.line,
                    severity=sev_map.get(issue.severity, Severity.MEDIUM), confidence=issue.confidence,
                    blast_radius=BlastRadius.SYSTEM, exploitability=0.9, category=Category.SECURITY,
                    cwe=issue.cwe, fix_suggestion=issue.fix))
        except Exception: pass
        # 4. IaC scanner
        try:
            from .iac_scanner import scan_iac
            for issue in scan_iac(self.repo_root, max_files=80):
                findings.append(Finding(layer=LayerID.L0_FAST, rule_id=issue.rule_id,
                    message=issue.description, file=issue.file, start_line=issue.line,
                    severity=sev_map.get(issue.severity, Severity.HIGH), confidence=issue.confidence,
                    blast_radius=BlastRadius.SYSTEM, exploitability=0.7, category=Category.SECURITY,
                    cwe=issue.cwe, fix_suggestion=issue.fix))
        except Exception: pass
        # 5. Supply chain (typosquats + Maven CVEs)
        try:
            from .supply_chain import analyze_supply_chain
            sc_findings, _sbom = analyze_supply_chain(self.repo_root)
            for issue in sc_findings:
                rule_id = f"L0b.sc.{issue.kind}"
                if issue.kind == "maven_cve": rule_id = f"L0b.sc.{issue.kind}.{issue.cve or issue.package}"
                findings.append(Finding(layer=LayerID.L0B_SUPPLY_CHAIN, rule_id=rule_id,
                    message=issue.description, file=f"{issue.package}@{issue.version}", start_line=1,
                    severity=sev_map.get(issue.severity, Severity.MEDIUM), confidence=issue.confidence,
                    blast_radius=BlastRadius.SYSTEM, exploitability=0.5, category=Category.SUPPLY_CHAIN,
                    cwe="CWE-1357", fix_suggestion=issue.fix))
        except Exception: pass
        # 6. Tree-sitter AST
        try:
            from .tree_sitter_analyzer import analyze_repo_with_ast
            for issue in analyze_repo_with_ast(self.repo_root, max_files=150):
                ast_cat = {"correctness":Category.CORRECTNESS,"maintainability":Category.MAINTAINABILITY,"security":Category.SECURITY}
                findings.append(Finding(layer=LayerID.L0_FAST, rule_id=f"L0.ast.{issue.rule_id}",
                    message=issue.description, file=issue.file, start_line=issue.line,
                    severity=sev_map.get(issue.severity, Severity.LOW), confidence=issue.confidence,
                    blast_radius=BlastRadius.FUNCTION, exploitability=0.4,
                    category=ast_cat.get(issue.category, Category.MAINTAINABILITY), cwe=issue.cwe, fix_suggestion=issue.fix))
        except Exception: pass
        return findings

    def _run_cross_file_taint_tracking_with_pysa(self, hunks: List[DiffHunk]) -> List[Finding]:
        """Run Pysa first (production-grade, Meta OSS); fall back to CPG taint tracker."""
        py_hunks = [h for h in hunks if h.file.endswith(".py")]
        if not py_hunks:
            return []

        # try Pysa first
        pysa = PysaIntegration(self.repo_root)
        if pysa.is_available():
            files = [self.repo_root / h.file for h in py_hunks]
            pysa_findings = pysa.run(files)
            if pysa_findings:
                self.audit.log("pysa_run", {"findings": len(pysa_findings)})
                return pysa_findings
            # Pysa found nothing — trust it (more accurate than CPG)
            return []

        # fall back to CPG taint tracker
        return self._run_cross_file_taint_tracking(hunks)

    def _run_advanced_secret_detection(self, hunks: List[DiffHunk]) -> List[Finding]:
        """Run TruffleHog + entropy-based secret detection on changed files."""
        files = []
        for hunk in hunks:
            file_path = self.repo_root / hunk.file
            if file_path.exists() and file_path.suffix in (".py", ".js", ".ts", ".jsx",
                                                            ".tsx", ".go", ".java", ".c",
                                                            ".cpp", ".h", ".yml", ".yaml",
                                                            ".json", ".env", ".txt", ".sh",
                                                            ".tf", ".cfg", ".conf", ".ini"):
                files.append(file_path)

        if not files:
            return []

        findings = detect_secrets_advanced(self.repo_root, files, scan_history=False)
        if findings:
            self.audit.log("secrets_detected", {"count": len(findings)})
        return findings

    def _run_hotspot_detection(self, hunks: List[DiffHunk]) -> List[Finding]:
        """Detect security hotspots (SonarQube-style, with review workflow)."""
        files = [self.repo_root / h.file for h in hunks if h.file.endswith((".py", ".js", ".ts", ".go", ".java"))]
        if not files:
            return []

        new_hotspots = self.hotspots.detect_hotspots(files)
        decayed = self.hotspots.get_decayed_hotspots()

        findings: List[Finding] = []
        for h in new_hotspots:
            findings.append(Finding(
                layer=LayerID.L0_FAST,
                rule_id=f"L0.hotspot.{h.category}",
                message=f"Security hotspot ({h.category}): {h.description}",
                file=h.file, start_line=h.line,
                severity=Severity.MEDIUM, confidence=0.6,
                blast_radius=BlastRadius.FUNCTION, exploitability=0.3,
                cwe="CWE-863",
                fix_suggestion=f"Review this hotspot: `stca hotspot review {h.id} safe|confirmed`",
                raw={"hotspot_id": h.id, "category": h.category},
            ))
        for h in decayed:
            findings.append(Finding(
                layer=LayerID.L0_FAST,
                rule_id=f"L0.hotspot.decayed.{h.category}",
                message=f"Hotspot needs re-review (marked safe 90+ days ago): {h.description}",
                file=h.file, start_line=h.line,
                severity=Severity.LOW, confidence=0.5,
                blast_radius=BlastRadius.FUNCTION, exploitability=0.2,
                cwe="CWE-863",
                fix_suggestion=f"Re-review: `stca hotspot review {h.id} safe|confirmed`",
                raw={"hotspot_id": h.id, "category": h.category, "decay": True},
            ))
        return findings

    def _run_coverage_checks(self, hunks: List[DiffHunk]) -> List[Finding]:
        """Check coverage for changed files; flag drops and low coverage."""
        report = find_coverage_report(self.repo_root)
        if not report:
            return []

        # track coverage history (writes to .stca-coverage-history.json)
        drops = track_coverage_history(self.repo_root, report)

        findings: List[Finding] = []
        for hunk in hunks:
            # find coverage for this file
            fc = report.files.get(hunk.file) or report.files.get(hunk.file.replace("/", "."))
            if not fc:
                continue
            # flag if coverage is <50% on a changed file
            if fc.line_rate < 0.5:
                findings.append(Finding(
                    layer=LayerID.L1_PROPERTY,
                    rule_id="L1.coverage.low",
                    message=f"Low coverage on changed file: {hunk.file} has {fc.line_rate*100:.0f}% line coverage",
                    file=hunk.file, start_line=0,
                    severity=Severity.MEDIUM, confidence=0.8,
                    blast_radius=BlastRadius.FUNCTION, exploitability=0.1,
                    cwe="CWE-1058",
                    fix_suggestion="Add tests for the changed code before merging",
                    raw={"line_rate": fc.line_rate, "branch_rate": fc.branch_rate},
                ))

        # flag coverage drops
        for file, drop in drops.items():
            findings.append(Finding(
                layer=LayerID.L1_PROPERTY,
                rule_id="L1.coverage.drop",
                message=f"Coverage dropped {drop*100:.0f}% in {file} — tests may have been removed or skipped",
                file=file, start_line=0,
                severity=Severity.HIGH, confidence=0.85,
                blast_radius=BlastRadius.FUNCTION, exploitability=0.0,
                cwe="CWE-1058",
                fix_suggestion="Restore the removed tests or add new ones for the changed code",
                raw={"drop": drop, "previous_rate": report.files.get(file, type("obj", (), {"line_rate": 0})).line_rate + drop},
            ))
        return findings

    def _run_cross_file_taint_tracking(self, hunks: List[DiffHunk]) -> List[Finding]:
        """Run CPG-based cross-file taint tracking on changed Python files.

        Replaces the old single-file taint tracker. This catches flows that
        span function calls and file boundaries — what CodeQL catches.
        """
        findings: List[Finding] = []
        py_hunks = [h for h in hunks if h.file.endswith(".py")]
        if not py_hunks:
            return findings

        try:
            # build CPG for the whole repo (cached after first build)
            cpg = build_cpg_for_repo(self.repo_root)
            if not cpg.nodes:
                return findings
            flows = track_taint_cross_file(cpg)
            for flow in flows:
                # only report flows that touch a changed file
                if not any(flow.sink_file == h.file for h in py_hunks):
                    continue
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id=f"L0.cpg_taint.{flow.sink}",
                    message=f"Cross-file taint flow: {flow.source} → {flow.sink}() in {flow.sink_function}() (CWE {flow.cwe}){' [cross-file]' if flow.cross_file else ''}",
                    file=flow.sink_file, start_line=flow.sink_line,
                    severity=Severity.CRITICAL if flow.cross_file else Severity.HIGH,
                    confidence=0.85,
                    blast_radius=BlastRadius.SYSTEM if flow.cross_file else BlastRadius.MODULE,
                    exploitability=0.9 if flow.cross_file else 0.75,
                    cwe=flow.cwe,
                    fix_suggestion=f"Sanitize input before passing to {flow.sink}()",
                    raw={"source": flow.source, "sink": flow.sink,
                         "cross_file": flow.cross_file,
                         "intermediate_functions": flow.intermediate_functions},
                ))
        except Exception as e:
            findings.append(Finding(
                layer=LayerID.L0_FAST,
                rule_id="L0.cpg_taint.error",
                message=f"CPG taint tracking failed: {e}",
                file="<pipeline>", start_line=0,
                severity=Severity.INFO, confidence=1.0,
            ))
        return findings

    def _run_typestate_analysis(self, hunks: List[DiffHunk]) -> List[Finding]:
        """Run typestate analysis on changed Python files (state machine violations)."""
        findings: List[Finding] = []
        seen_files: set = set()
        for hunk in hunks:
            if not hunk.file.endswith(".py") or hunk.file in seen_files:
                continue
            seen_files.add(hunk.file)
            file_path = self.repo_root / hunk.file
            if not file_path.exists():
                continue
            violations = analyze_typestate(file_path)
            for v in violations:
                # only report violations on changed lines
                if not any(h.file == v.file and h.start_line <= v.line <= h.end_line
                           for h in hunks):
                    continue
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id=f"L0.typestate.{v.violation}",
                    message=f"Typestate violation: {v.description}",
                    file=v.file, start_line=v.line,
                    severity=Severity.HIGH, confidence=0.8,
                    blast_radius=BlastRadius.MODULE, exploitability=0.5,
                    cwe=v.cwe,
                    fix_suggestion=f"Ensure proper state machine: {v.description}",
                    raw={"object": v.object_name, "protocol": v.protocol,
                         "violation": v.violation},
                ))
        return findings

    def _run_cpg_queries(self, hunks: List[DiffHunk]) -> List[Finding]:
        """Run Joern-style CPG pattern queries."""
        findings: List[Finding] = []
        py_hunks = [h for h in hunks if h.file.endswith(".py")]
        if not py_hunks:
            return findings
        try:
            cpg = build_cpg_for_repo(self.repo_root)
            if not cpg.nodes:
                return findings

            # query 1: unsanitized taint flows
            for result in query_unsanitized_taint_flows(cpg):
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id="L0.cpg_query.unsanitized_taint",
                    message=f"CPG query: {result.description}",
                    file=result.file, start_line=result.line,
                    severity=Severity.HIGH, confidence=0.85,
                    blast_radius=BlastRadius.MODULE, exploitability=0.8,
                    cwe="CWE-20",
                    raw=result.raw or {},
                ))

            # query 2: dangerous patterns in auth code
            for result in query_dangerous_patterns_in_auth(cpg):
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id="L0.cpg_query.auth_dangerous",
                    message=f"CPG query: {result.description}",
                    file=result.file, start_line=result.line,
                    severity=Severity.CRITICAL, confidence=0.9,
                    blast_radius=BlastRadius.SYSTEM, exploitability=0.95,
                    cwe="CWE-863",
                    raw=result.raw or {},
                ))

            # query 3: high-complexity functions
            for result in query_function_complexity(cpg, threshold=15):
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id="L0.cpg_query.high_complexity",
                    message=f"CPG query: {result.description}",
                    file=result.file, start_line=result.line,
                    severity=Severity.LOW, confidence=0.85,
                    blast_radius=BlastRadius.FUNCTION, exploitability=0.0,
                    cwe="CWE-1058",
                    raw=result.raw or {},
                ))
        except Exception:
            pass
        return findings

    def _run_metamorphic_tests(self, hunks: List[DiffHunk]) -> List[Finding]:
        """Run metamorphic tests on changed Python files (oracle-free bug detection)."""
        findings: List[Finding] = []
        seen_files: set = set()
        for hunk in hunks:
            if not hunk.file.endswith(".py") or hunk.file in seen_files:
                continue
            seen_files.add(hunk.file)
            file_path = self.repo_root / hunk.file
            if not file_path.exists():
                continue
            violations = run_metamorphic_tests(file_path, self.repo_root)
            for v in violations:
                findings.append(Finding(
                    layer=LayerID.L1_PROPERTY,
                    rule_id=f"L1.metamorphic.{v.relation}",
                    message=f"Metamorphic violation in {v.function}(): {v.relation} — {v.description}",
                    file=v.file, start_line=0,
                    severity=Severity.HIGH, confidence=0.7,
                    blast_radius=BlastRadius.FUNCTION, exploitability=0.2,
                    cwe="CWE-838",  # improper neutralization
                    raw={"function": v.function, "relation": v.relation,
                         "input_summary": v.input_summary},
                ))
        return findings

    def _run_differential_tests(self, hunks: List[DiffHunk]) -> List[Finding]:
        """Run differential tests on changed Python files (refactor verification)."""
        findings: List[Finding] = []
        seen_files: set = set()
        for hunk in hunks:
            if not hunk.file.endswith(".py") or hunk.file in seen_files:
                continue
            seen_files.add(hunk.file)
            file_path = self.repo_root / hunk.file
            if not file_path.exists():
                continue
            bugs = run_differential_tests(file_path, self.repo_root)
            for b in bugs:
                findings.append(Finding(
                    layer=LayerID.L1_PROPERTY,
                    rule_id="L1.differential",
                    message=f"Differential bug: {b.function_a}() vs {b.function_b}() disagree on input — {b.input_summary[:100]}",
                    file=b.file, start_line=0,
                    severity=Severity.HIGH, confidence=0.85,
                    blast_radius=BlastRadius.FUNCTION, exploitability=0.3,
                    cwe="CWE-838",
                    raw={"function_a": b.function_a, "function_b": b.function_b,
                         "output_a": b.output_a, "output_b": b.output_b},
                ))
        return findings

    def _is_iac_file(self, file_path: str) -> bool:
        """Check if a file is an IaC file (Dockerfile, K8s, Terraform, etc.)."""
        from pathlib import Path
        p = Path(file_path)
        name = p.name.lower()
        if name.startswith("dockerfile") or name.endswith(".dockerfile"):
            return True
        if p.suffix in (".tf", ".tfvars"):
            return True
        if file_path.startswith(".github/workflows/") and p.suffix in (".yml", ".yaml"):
            return True
        if any(x in file_path.lower() for x in ["k8s", "kubernetes", "manifest", "deploy"]):
            if p.suffix in (".yaml", ".yml"):
                return True
        return False

    def _has_any_iac_files(self) -> bool:
        """Quick check: does the repo have any IaC files at all?"""
        from pathlib import Path
        for pattern in ["**/Dockerfile*", "**/*.tf", ".github/workflows/*.yml"]:
            try:
                if any(Path(self.repo_root).glob(pattern)):
                    return True
            except Exception:
                continue
        return False

    def _llm_tie_break(self, finding: Finding) -> Optional[AggregatedDecision]:
        """Invoke the LLM tie-breaker for an uncertain finding, gated by PRM."""
        if not self.llm or not self.llm.is_available():
            return None

        finding_summary = (
            f"[{finding.layer.value}] {finding.rule_id}: {finding.message} "
            f"(severity={finding.severity.value}, confidence={finding.confidence:.0%})"
        )
        function_body = ""
        for hunk in []:  # would need to pass hunks in
            pass
        # use raw if available
        function_body = finding.raw.get("function_body", "") or finding.raw.get("line", "")

        response = self.llm.review_finding(finding_summary, function_body)
        if not response:
            return None

        prm_result = self.prm.score_reasoning(response, function_body)
        threshold = float(self.config.llm.get("prm_threshold", 0.6))
        if not prm_result["verdict_trusted"] or prm_result["overall_prm_score"] < threshold:
            # PRM says LLM is hallucinating — drop the LLM input, keep UNCERTAIN
            return AggregatedDecision(
                decision=Decision.UNCERTAIN,
                confidence_interval=(0.4, 0.6),
                contributing_signals={"llm_prm_score": prm_result["overall_prm_score"],
                                      "llm_verdict": response.get("verdict", "uncertain"),
                                      "prm_trusted": False},
                reasoning=f"LLM tie-breaker invoked but PRM score {prm_result['overall_prm_score']:.2f} < threshold {threshold} — LLM input discarded",
            )

        # PRM trusts the LLM — convert verdict to decision
        verdict = response.get("verdict", "uncertain")
        llm_conf = float(response.get("confidence", 0.5))
        if verdict == "confirmed":
            new_decision = Decision.WARN if llm_conf < 0.7 else Decision.BLOCK
        elif verdict == "false_positive":
            new_decision = Decision.PASS
        else:
            new_decision = Decision.WARN

        return AggregatedDecision(
            decision=new_decision,
            confidence_interval=(llm_conf * 0.9, llm_conf),
            contributing_signals={
                "llm_verdict": verdict,
                "llm_confidence": llm_conf,
                "llm_prm_score": prm_result["overall_prm_score"],
                "suggested_fix": response.get("suggested_fix"),
            },
            reasoning=f"LLM tie-breaker (PRM score {prm_result['overall_prm_score']:.2f}): verdict={verdict}, confidence={llm_conf:.2f} → {new_decision.value}",
        )

    def _save_reports(self, result: PipelineResult) -> None:
        """Persist JSON, SARIF, and HTML reports."""
        from .report.sarif import save_sarif
        from .report.html import save_html

        report_dir = self.repo_root / self.config.report_dir
        report_dir.mkdir(parents=True, exist_ok=True)

        # JSON
        result.to_json(report_dir / "result.json")

        # SARIF
        save_sarif(result, self.repo_root, report_dir / "result.sarif")

        # HTML
        save_html(result, self.repo_root, report_dir / "report.html")
