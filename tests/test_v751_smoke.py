#!/usr/bin/env python3
"""v7.5.1 smoke tests — invoke each new CLI command to catch runtime errors.

This test exists because v7.5.0 shipped with 3 bugs that basic smoke tests
would have caught:
  1. gnn_cpg.py NameError when torch not installed
  2. jsx-auth CLI calling .detect() (doesn't exist, should be .analyze())
  3. multi-call scanning LoomScan's own .loomscan-cache/ output files

Each test invokes a CLI command with --help (verifies the command is wired)
and then with a minimal fixture (verifies it runs without AttributeError /
NameError / etc.).
"""
import sys
import tempfile
from pathlib import Path

# v7.5.3: Fixed hardcoded /home/z/my-project path — now uses relative path
# from this test file to the project root. Works on any machine / CI.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from click.testing import CliRunner
from loomscan.cli import (
    jsx_auth, stateful_pbt, multi_call,
    gnn_score, gnn_train,
    learn, second_opinion, diff,
)


def test_jsx_auth_help():
    """jsx-auth --help should not raise."""
    runner = CliRunner()
    result = runner.invoke(jsx_auth, ["--help"])
    assert result.exit_code == 0, f"jsx-auth --help failed: {result.output}"
    assert "JSX/React authorization" in result.output


def test_jsx_auth_runs_on_empty_repo():
    """jsx-auth should run on an empty repo without AttributeError."""
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as td:
        result = runner.invoke(jsx_auth, ["--repo", td])
        # Should exit 0 (no violations found on empty repo)
        assert result.exit_code == 0, f"jsx-auth failed: {result.output}"
        assert "0 auth pattern" in result.output or "0 page" in result.output or "Found 0" in result.output


def test_stateful_pbt_help():
    """stateful-pbt --help should not raise."""
    runner = CliRunner()
    result = runner.invoke(stateful_pbt, ["--help"])
    assert result.exit_code == 0, f"stateful-pbt --help failed: {result.output}"
    assert "Stateful property-based testing" in result.output


def test_stateful_pbt_runs_on_empty_repo():
    """stateful-pbt should run on an empty repo without errors."""
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as td:
        result = runner.invoke(stateful_pbt, ["--repo", td])
        assert result.exit_code == 0, f"stateful-pbt failed: {result.output}"


def test_multi_call_help():
    """multi-call --help should not raise."""
    runner = CliRunner()
    result = runner.invoke(multi_call, ["--help"])
    assert result.exit_code == 0, f"multi-call --help failed: {result.output}"
    assert "Multi-call bug detection" in result.output


def test_multi_call_runs_on_empty_repo():
    """multi-call should run on an empty repo without errors."""
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as td:
        result = runner.invoke(multi_call, ["--repo", td])
        assert result.exit_code == 0, f"multi-call failed: {result.output}"
        assert "Scanned 0" in result.output or "No multi-call violations" in result.output


def test_multi_call_skips_loomscan_cache():
    """multi-call should NOT scan .loomscan-cache/ files (feedback-loop fix)."""
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        # Create a .loomscan-cache dir with a fake test file that would trigger TOCTOU
        cache_dir = repo / ".loomscan-cache" / "metamorphic"
        cache_dir.mkdir(parents=True)
        (cache_dir / "test_vulns.py").write_text("""
balances = {}
def transfer(account, amount):
    balance = get_balance(account)
    if balance >= amount:
        external_call(account, amount)
        deduct(account, amount)
def get_balance(account): return balances[account]
def external_call(account, amount): pass
def deduct(account, amount): balances[account] -= amount
""")
        result = runner.invoke(multi_call, ["--repo", str(repo)])
        # Should scan 0 files (the only .py file is in .loomscan-cache which is skipped)
        assert "Scanned 0" in result.output, \
            f"multi-call scanned .loomscan-cache files! Output: {result.output}"


def test_gnn_score_help():
    """gnn-score --help should not raise."""
    runner = CliRunner()
    result = runner.invoke(gnn_score, ["--help"])
    assert result.exit_code == 0, f"gnn-score --help failed: {result.output}"
    assert "GNN" in result.output


def test_gnn_train_help():
    """gnn-train --help should not raise."""
    runner = CliRunner()
    result = runner.invoke(gnn_train, ["--help"])
    assert result.exit_code == 0, f"gnn-train --help failed: {result.output}"
    assert "Train the GNN" in result.output


def test_learn_help():
    """learn --help should not raise."""
    runner = CliRunner()
    result = runner.invoke(learn, ["--help"])
    assert result.exit_code == 0, f"learn --help failed: {result.output}"
    assert "Active learning" in result.output


def test_second_opinion_help():
    """second-opinion --help should not raise."""
    runner = CliRunner()
    result = runner.invoke(second_opinion, ["--help"])
    assert result.exit_code == 0, f"second-opinion --help failed: {result.output}"
    assert "ExplainableAggregator" in result.output or "second opinion" in result.output.lower()


def test_diff_help():
    """diff --help should not raise."""
    runner = CliRunner()
    result = runner.invoke(diff, ["--help"])
    assert result.exit_code == 0, f"diff --help failed: {result.output}"
    assert "Differential" in result.output or "baseline" in result.output.lower()


def test_gnn_cpg_imports_without_torch():
    """gnn_cpg.py should import cleanly even when torch is not installed."""
    import importlib
    import sys
    # Save original state
    original_torch = sys.modules.get("torch")
    original_tg = sys.modules.get("torch_geometric")
    # Remove torch to simulate missing dep
    sys.modules["torch"] = None
    sys.modules["torch_geometric"] = None
    try:
        # Force reimport
        if "loomscan.gnn_cpg" in sys.modules:
            del sys.modules["loomscan.gnn_cpg"]
        from loomscan.gnn_cpg import is_gnn_available, build_cpg, GNNOnCPGModel
        assert is_gnn_available() == False, "GNN should be unavailable without torch"
        # build_cpg should still work (doesn't need torch)
        cpg = build_cpg("def f(x): return x", "f", 1)
        assert cpg is not None
        assert len(cpg.nodes) > 0
    finally:
        # Restore
        if original_torch is not None:
            sys.modules["torch"] = original_torch
        else:
            del sys.modules["torch"]
        if original_tg is not None:
            sys.modules["torch_geometric"] = original_tg
        else:
            del sys.modules["torch_geometric"]
        # Force reimport to restore real state
        if "loomscan.gnn_cpg" in sys.modules:
            del sys.modules["loomscan.gnn_cpg"]


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v", "--tb=short"]))
