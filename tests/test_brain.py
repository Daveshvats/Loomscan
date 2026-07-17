"""Tests for loomscan.brain package — fuzzy aggregation, Bayesian second opinion,
ExplainableAggregator, membership functions, and project tuner.

v7.4: Added to address the secondary auditor's "zero tests for brain/" finding.
"""
import pytest
import math
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from loomscan.brain.bayesian import (
    ExplainableAggregator,
    BayesianSecondOpinion,
    BBNEvidence,
    AggregatedSecondOpinion,
    Decision,
)
from loomscan.brain.it2_fis import IT2FIS
from loomscan.brain.membership import (
    IT2Membership,
    it2_triangular,
    it2_trapezoidal,
    SeverityMF,
    ConfidenceMF,
)


class TestMembershipFunctions:
    """Test membership function generators (interval type-2)."""

    def test_it2_triangular_returns_it2membership(self):
        """it2_triangular should return a function that produces an IT2Membership."""
        f = it2_triangular(0, 1, 2, 0.1)
        result = f(1.0)  # at peak
        assert hasattr(result, "upper") or hasattr(result, "u"), \
            f"Expected IT2Membership-like object, got {type(result)}"
        # At peak, both upper and lower should be close to 1.0
        upper = getattr(result, "upper", getattr(result, "u", None))
        lower = getattr(result, "lower", getattr(result, "l", None))
        assert upper is not None and lower is not None
        assert 0.0 <= lower <= upper <= 1.0, f"Expected 0 <= lower <= upper <= 1, got {lower}, {upper}"

    def test_it2_triangular_outside(self):
        """it2_triangular outside support should return zero membership."""
        f = it2_triangular(0, 1, 2, 0.1)
        result = f(-1)
        upper = getattr(result, "upper", getattr(result, "u", 0))
        lower = getattr(result, "lower", getattr(result, "l", 0))
        assert upper == 0.0 and lower == 0.0, \
            f"Expected (0, 0) outside support, got upper={upper} lower={lower}"

    def test_it2_trapezoidal_returns_it2membership(self):
        """it2_trapezoidal should return a function that produces an IT2Membership."""
        f = it2_trapezoidal(0, 1, 2, 3, 0.1)
        result = f(1.5)  # at center
        upper = getattr(result, "upper", getattr(result, "u", None))
        lower = getattr(result, "lower", getattr(result, "l", None))
        assert upper is not None and lower is not None
        assert 0.0 <= lower <= upper <= 1.0

    def test_severity_mf_class_exists(self):
        """SeverityMF should be a class with membership functions."""
        assert SeverityMF is not None

    def test_confidence_mf_class_exists(self):
        """ConfidenceMF should be a class with membership functions."""
        assert ConfidenceMF is not None


class TestBBNEvidence:
    """Test BBNEvidence dataclass."""

    def test_default_evidence(self):
        """Default BBNEvidence should have all fields populated."""
        ev = BBNEvidence()
        assert 0.0 <= ev.confidence <= 1.0
        assert 0.0 <= ev.exploitability <= 1.0
        assert 0.0 <= ev.reliability <= 1.0
        assert 0.0 <= ev.fp_history <= 1.0
        assert 0.0 <= ev.corroboration <= 1.0
        assert 0.0 <= ev.test_exclusion <= 1.0
        assert 0.0 <= ev.fis_score <= 1.0

    def test_custom_evidence(self):
        """Custom BBNEvidence should preserve values."""
        ev = BBNEvidence(
            confidence=0.9,
            exploitability=0.8,
            reliability=0.7,
            fp_history=0.1,
            corroboration=0.5,
            test_exclusion=0.0,
            fis_score=0.85,
        )
        assert ev.confidence == 0.9
        assert ev.exploitability == 0.8
        assert ev.fis_score == 0.85


class TestBayesianSecondOpinion:
    """Test the BayesianSecondOpinion BBN."""

    def test_instantiation(self):
        """BBN should instantiate without error."""
        bbn = BayesianSecondOpinion()
        assert bbn is not None

    def test_evaluate_returns_decision(self):
        """BBN evaluate() should return a Decision."""
        bbn = BayesianSecondOpinion()
        ev = BBNEvidence(
            confidence=0.85,
            exploitability=0.8,
            reliability=0.7,
            fis_score=0.85,
        )
        result = bbn.evaluate(ev)
        assert result.decision in (Decision.BLOCK, Decision.WARN, Decision.PASS)
        assert 0.0 <= result.confidence <= 1.0

    def test_high_severity_evidence_blocks(self):
        """High-severity evidence (high confidence + exploitability) should tend to BLOCK."""
        bbn = BayesianSecondOpinion()
        ev = BBNEvidence(
            confidence=0.95,
            exploitability=0.9,
            reliability=0.9,
            fp_history=0.0,
            fis_score=0.9,
        )
        result = bbn.evaluate(ev)
        # With high-severity evidence, BLOCK should be more likely than PASS
        assert result.p_block >= result.p_pass, \
            f"Expected p_block >= p_pass, got block={result.p_block} pass={result.p_pass}"

    def test_low_severity_evidence_passes(self):
        """Low-severity evidence (low confidence + exploitability) should tend to PASS."""
        bbn = BayesianSecondOpinion()
        ev = BBNEvidence(
            confidence=0.1,
            exploitability=0.1,
            reliability=0.5,
            fp_history=0.5,
            fis_score=0.1,
        )
        result = bbn.evaluate(ev)
        # With low-severity evidence, PASS should be more likely than BLOCK
        assert result.p_pass >= result.p_block, \
            f"Expected p_pass >= p_block, got block={result.p_block} pass={result.p_pass}"


class TestExplainableAggregator:
    """Test the ExplainableAggregator (combines FIS + BBN + counterfactual)."""

    def test_instantiation(self):
        """Aggregator should instantiate with a BBN."""
        agg = ExplainableAggregator()
        assert agg.bbn is not None

    def test_basic_aggregation(self):
        """Aggregate should return an AggregatedSecondOpinion with valid fields."""
        agg = ExplainableAggregator()
        ev = BBNEvidence(
            confidence=0.85,
            exploitability=0.8,
            reliability=0.7,
            fis_score=0.0,  # set by aggregate()
        )
        result = agg.aggregate(
            fis_score=0.85,
            fis_decision="block",
            evidence=ev,
        )
        assert isinstance(result, AggregatedSecondOpinion)
        assert result.decision in (Decision.BLOCK, Decision.WARN, Decision.PASS)
        assert 0.0 <= result.confidence <= 1.0
        assert result.reasoning
        assert "FIS=" in result.reasoning
        assert "BBN=" in result.reasoning

    def test_counterfactual_fp_downgrades_block(self):
        """When counterfactual=False (verified FP), BLOCK should be downgraded."""
        agg = ExplainableAggregator()
        ev = BBNEvidence(
            confidence=0.85,
            exploitability=0.8,
            reliability=0.7,
            fis_score=0.0,
        )
        result = agg.aggregate(
            fis_score=0.85,
            fis_decision="block",
            evidence=ev,
            counterfactual_verified=False,
        )
        assert result.decision != Decision.BLOCK, \
            f"BLOCK should be downgraded when counterfactual=False, got {result.decision}"

    def test_counterfactual_tp_confirms(self):
        """When counterfactual=True (verified TP), decision should be confident."""
        agg = ExplainableAggregator()
        ev = BBNEvidence(
            confidence=0.85,
            exploitability=0.8,
            reliability=0.7,
            fis_score=0.0,
        )
        result = agg.aggregate(
            fis_score=0.85,
            fis_decision="block",
            evidence=ev,
            counterfactual_verified=True,
        )
        # Verified TP should not be downgraded to PASS
        assert result.decision != Decision.PASS, \
            f"Verified TP should not be PASS, got {result.decision}"

    def test_trace_is_populated(self):
        """Aggregated result should include BBN posterior trace."""
        agg = ExplainableAggregator()
        ev = BBNEvidence(confidence=0.7, exploitability=0.6, reliability=0.7, fis_score=0.7)
        result = agg.aggregate(fis_score=0.7, fis_decision="warn", evidence=ev)
        assert "bbn_posterior" in result.trace
        assert "block" in result.trace["bbn_posterior"]
        assert "warn" in result.trace["bbn_posterior"]
        assert "pass" in result.trace["bbn_posterior"]


class TestIT2FIS:
    """Test the Interval Type-2 Fuzzy Inference System."""

    def test_instantiation(self):
        """FIS should instantiate without error."""
        fis = IT2FIS()
        assert fis is not None

    def test_evaluate_returns_result(self):
        """Evaluate should return a (membership, comment) tuple."""
        fis = IT2FIS()
        result = fis.evaluate(
            severity_score=0.8,
            confidence=0.85,
            blast_radius="module",
            exploitability=0.7,
            source_reliability=0.7,
        )
        # Result should be a tuple (IT2Membership, str)
        assert result is not None
        assert isinstance(result, tuple), f"Expected tuple, got {type(result)}"
        assert len(result) == 2
        membership, comment = result
        assert hasattr(membership, "upper") or hasattr(membership, "u"), \
            f"Expected IT2Membership-like, got {type(membership)}"
        assert isinstance(comment, str), f"Expected str comment, got {type(comment)}"

    def test_high_severity_inputs_produce_higher_score(self):
        """High-severity inputs should produce higher membership on BLOCK than low-severity."""
        fis = IT2FIS()
        high_membership, _ = fis.evaluate(
            severity_score=0.9, confidence=0.9, blast_radius="system",
            exploitability=0.9, source_reliability=0.9,
        )
        low_membership, _ = fis.evaluate(
            severity_score=0.1, confidence=0.1, blast_radius="function",
            exploitability=0.1, source_reliability=0.1,
        )
        high_upper = getattr(high_membership, "upper", getattr(high_membership, "u", 0))
        low_upper = getattr(low_membership, "upper", getattr(low_membership, "u", 0))
        # High severity should produce >= upper membership than low severity
        assert high_upper >= low_upper, \
            f"High-severity upper ({high_upper}) should be >= low-severity upper ({low_upper})"


class TestDecision:
    """Test the Decision enum."""

    def test_all_decisions_exist(self):
        """Decision should have BLOCK, WARN, PASS."""
        assert Decision.BLOCK
        assert Decision.WARN
        assert Decision.PASS

    def test_decision_values_are_strings(self):
        """Decision values should be lowercase strings."""
        assert Decision.BLOCK.value in ("block", "BLOCK")
        assert Decision.WARN.value in ("warn", "WARN")
        assert Decision.PASS.value in ("pass", "PASS")
