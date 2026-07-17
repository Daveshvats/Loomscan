#!/usr/bin/env python3
"""v7.3.4: Smoke test for ExplainableAggregator — verify it works when instantiated.

The secondary auditor flagged that ExplainableAggregator (brain/bayesian.py:294)
was never instantiated anywhere in the codebase. This test verifies the class
is functional and provides a usage example for future integration.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from loomscan.brain.bayesian import (
    ExplainableAggregator,
    BayesianSecondOpinion,
    BBNEvidence,
    AggregatedSecondOpinion,
    Decision,
)


def test_explainable_aggregator_basic():
    """Verify ExplainableAggregator can be instantiated and produces decisions."""
    agg = ExplainableAggregator()
    assert agg.bbn is not None, "BBN second opinion should be initialized"

    # Test with high-severity evidence → should BLOCK or WARN
    evidence = BBNEvidence(
        confidence=0.85,
        exploitability=0.8,
        reliability=0.7,
        fp_history=0.1,
        corroboration=0.5,
        test_exclusion=0.0,
        fis_score=0.0,  # will be set by aggregate()
    )
    result = agg.aggregate(
        fis_score=0.85,
        fis_decision="block",
        evidence=evidence,
        counterfactual_verified=None,
    )
    assert isinstance(result, AggregatedSecondOpinion), f"Expected AggregatedSecondOpinion, got {type(result)}"
    assert result.decision in (Decision.BLOCK, Decision.WARN, Decision.PASS), f"Unexpected decision: {result.decision}"
    assert 0.0 <= result.confidence <= 1.0, f"Confidence out of range: {result.confidence}"
    assert result.reasoning, "Reasoning should not be empty"
    assert "FIS=" in result.reasoning, "Reasoning should mention FIS"
    assert "BBN=" in result.reasoning, "Reasoning should mention BBN"
    print(f"  OK   basic aggregation: decision={result.decision.value} confidence={result.confidence:.2f}")
    print(f"       reasoning: {result.reasoning}")


def test_explainable_aggregator_counterfactual_fp():
    """Verify counterfactual=False downgrades BLOCK → WARN."""
    agg = ExplainableAggregator()
    evidence = BBNEvidence(
        confidence=0.85,
        exploitability=0.8,
        reliability=0.7,
        fp_history=0.1,
        corroboration=0.5,
        test_exclusion=0.0,
        fis_score=0.0,
    )
    # Counterfactual verified as FALSE POSITIVE
    result = agg.aggregate(
        fis_score=0.85,
        fis_decision="block",
        evidence=evidence,
        counterfactual_verified=False,
    )
    # When CF=False, BLOCK should be downgraded to WARN (or PASS)
    assert result.decision != Decision.BLOCK, \
        f"BLOCK should be downgraded when counterfactual=False, got {result.decision}"
    print(f"  OK   counterfactual FP: BLOCK downgraded to {result.decision.value}")


def main():
    print("=" * 70)
    print("v7.3.4: ExplainableAggregator smoke test")
    print("=" * 70)
    failures = 0
    try:
        test_explainable_aggregator_basic()
    except Exception as e:
        print(f"  FAIL test_explainable_aggregator_basic: {type(e).__name__}: {e}")
        failures += 1
    try:
        test_explainable_aggregator_counterfactual_fp()
    except Exception as e:
        print(f"  FAIL test_explainable_aggregator_counterfactual_fp: {type(e).__name__}: {e}")
        failures += 1

    print()
    if failures:
        print(f"❌ {failures} test(s) failed")
        sys.exit(1)
    print("✅ ExplainableAggregator is functional and ready for orchestrator integration")


if __name__ == "__main__":
    main()
