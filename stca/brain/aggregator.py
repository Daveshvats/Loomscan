"""Aggregator: feeds findings into the IT2-FIS and produces decisions.

This is the deterministic "brain" — it never calls an LLM, never makes a
non-reproducible decision. Every finding gets a (decision, confidence_interval)
pair. The diff as a whole gets a single final_decision = max over findings.
"""
from __future__ import annotations

from typing import List, Tuple, Dict
from pathlib import Path
import json

from ..models import (
    Finding, AggregatedDecision, Decision, LayerID, PipelineResult, LayerStats,
)
from .it2_fis import IT2FIS, decision_from_score
from .membership import IT2Membership


class Aggregator:
    """Combines findings via the IT2-FIS."""

    def __init__(self, stats_path: Path = None):
        self.fis = IT2FIS()
        self.stats_path = stats_path
        self.layer_stats: Dict[str, LayerStats] = {}
        self._load_stats()

    def _load_stats(self):
        """Load per-layer precision/recall stats for source reliability scoring."""
        if not self.stats_path or not self.stats_path.exists():
            return
        try:
            data = json.loads(self.stats_path.read_text(encoding="utf-8"))
            for layer_id, s in data.get("layers", {}).items():
                self.layer_stats[layer_id] = LayerStats(
                    layer=layer_id,
                    true_positives=s.get("tp", 0),
                    false_positives=s.get("fp", 0),
                    bugs_missed=s.get("fn", 0),
                )
        except Exception:
            pass

    def get_reliability(self, layer_id: str) -> float:
        """Get the historical reliability score for a layer (0..1)."""
        stats = self.layer_stats.get(layer_id)
        if stats:
            return stats.reliability_score
        return 0.5  # neutral prior for unknown layers

    def aggregate_finding(self, finding: Finding) -> AggregatedDecision:
        """Run the FIS on a single finding."""
        reliability = self.get_reliability(finding.layer.value)
        output_mem, rule_comment = self.fis.evaluate(
            severity_score=finding.severity_score(),
            confidence=finding.confidence,
            blast_radius=finding.blast_radius.value,
            exploitability=finding.exploitability,
            source_reliability=reliability,
        )

        # convert to decision
        score = output_mem.midpoint
        decision_str = decision_from_score(score)

        # if uncertainty is very high AND the score is genuinely borderline,
        # mark UNCERTAIN to trigger the LLM tie-breaker.
        # Tight criteria: must be both very uncertain AND very close to the
        # warn/pass or warn/block boundary.
        if output_mem.uncertainty > 0.5 and 0.35 < score < 0.65:
            decision = Decision.UNCERTAIN
        else:
            decision = Decision(decision_str)

        return AggregatedDecision(
            decision=decision,
            confidence_interval=(output_mem.lower, output_mem.upper),
            contributing_signals={
                "severity": finding.severity_score(),
                "confidence": finding.confidence,
                "blast_radius": finding.blast_radius.value,
                "exploitability": finding.exploitability,
                "source_reliability": reliability,
                "firing_rule": rule_comment,
            },
            reasoning=f"FIS fired rule: '{rule_comment}'. "
                      f"Output interval [{output_mem.lower:.2f}, {output_mem.upper:.2f}], "
                      f"midpoint {score:.2f} → {decision_str}. "
                      f"Uncertainty footprint: {output_mem.uncertainty:.2f}.",
        )

    def aggregate(self, findings: List[Finding]) -> Tuple[List[AggregatedDecision], Decision]:
        """Aggregate all findings. Returns (per-finding decisions, final overall decision)."""
        decisions = [self.aggregate_finding(f) for f in findings]

        if not decisions:
            return [], Decision.PASS

        # final decision = the most severe individual decision
        # block > warn > uncertain > pass
        priority = {Decision.BLOCK: 4, Decision.WARN: 3,
                    Decision.UNCERTAIN: 2, Decision.PASS: 1}
        final = max(decisions, key=lambda d: priority[d.decision]).decision
        return decisions, final
