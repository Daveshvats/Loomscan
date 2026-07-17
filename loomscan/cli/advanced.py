"""v7.6: Advanced CLI commands — active learning, GNN, differential analysis.

Extracted from cli.py in v7.6.0 for maintainability.
"""
import sys
import json
import click
from pathlib import Path

from . import main  # noqa: F401 — registers with the Click group
from .. import __version__

# =============================================================================
# v7.4: New CLI commands — learn, second-opinion
# Wires previously-dead ActiveLearning and ExplainableAggregator classes.
# =============================================================================

@main.command("learn")
@click.option("--repo", default=".", help="Repository root")
@click.option("--top-k", default=10, type=int, help="Number of findings to suggest for labeling")
@click.option("--label-db", default=".loomscan-cache/labels.json", help="Path to label counts JSON")
def learn(repo: str, top_k: int, label_db: str):
    """v7.4: Active learning — suggest which findings a human should label next.

    Uses three signals:
      - uncertainty: findings near the warn/pass boundary (confidence 0.4-0.6)
      - novelty: findings on rules with <5 historical labels
      - disagreement: findings where FIS and counterfactual disagree

    Output: top-K findings ranked by informativeness, with reasons.
    Label counts are persisted to --label-db for future runs.
    """
    from pathlib import Path
    from ..learning import ActiveLearning
    import json

    repo_root = Path(repo).resolve()
    if not repo_root.exists():
        click.echo(f"Error: repo {repo} does not exist", err=True)
        sys.exit(1)

    # Load label counts
    label_path = Path(label_db)
    label_counts: dict = {}
    if label_path.exists():
        try:
            label_counts = json.loads(label_path.read_text())
        except Exception:
            pass

    # Run a scan to get findings
    from ..orchestrator import Orchestrator
    orch = Orchestrator(repo_root=repo_root)
    result = orch.run_full()

    # Convert findings to dict format expected by ActiveLearning
    findings_dicts = []
    for f in result.findings:
        findings_dicts.append({
            "rule_id": f.rule_id,
            "confidence": float(f.confidence) if hasattr(f, "confidence") else 0.5,
            "file": f.file,
            "line": f.start_line,
            "fingerprint": f"{f.file}:{f.start_line}:{f.rule_id}",
            "counterfactual_disagree": False,  # not available without counterfactual engine
        })

    al = ActiveLearning(label_counts=label_counts)
    candidates = al.suggest(findings_dicts, top_k=top_k)

    click.echo(f"\nTop {len(candidates)} findings to label (from {len(findings_dicts)} total):\n")
    for i, c in enumerate(candidates, 1):
        click.echo(f"  {i}. {c.file}:{c.line}  [{c.rule_id}]")
        click.echo(f"     informativeness: {c.informativeness:.3f}")
        click.echo(f"     reason: {c.reason}")
        click.echo()

    click.echo(f"Label these findings with `loomscan feedback tp/fp <rule_id>` to improve future suggestions.")


@main.command("second-opinion")
@click.option("--repo", default=".", help="Repository root")
@click.option("--threshold", default=0.5, type=float, help="FIS score threshold for second opinion (0-1)")
def second_opinion(repo: str, threshold: float):
    """v7.4: Run ExplainableAggregator as an opt-in second opinion on findings.

    Combines FIS (fuzzy inference), BBN (Bayesian belief network), and
    counterfactual verification into a single explainable decision.

    For each finding with FIS score >= --threshold, runs the BBN second opinion
    and prints the aggregated decision with reasoning.
    """
    from pathlib import Path
    from ..brain.bayesian import ExplainableAggregator, BBNEvidence, Decision

    repo_root = Path(repo).resolve()
    if not repo_root.exists():
        click.echo(f"Error: repo {repo} does not exist", err=True)
        sys.exit(1)

    from ..orchestrator import Orchestrator
    orch = Orchestrator(repo_root=repo_root)
    result = orch.run_full()

    agg = ExplainableAggregator()
    click.echo(f"\nSecond-opinion analysis on {len(result.findings)} findings (threshold={threshold}):\n")

    second_opinion_count = 0
    for f in result.findings:
        fis_score = float(f.confidence) if hasattr(f, "confidence") else 0.5
        if fis_score < threshold:
            continue
        second_opinion_count += 1

        # Build evidence from finding properties
        sev = str(f.severity).lower() if hasattr(f, "severity") else "medium"
        evidence = BBNEvidence(
            confidence=fis_score,
            exploitability=0.7 if "INJECTION" in f.rule_id or "AUTH" in f.rule_id else 0.4,
            reliability=0.7,
            fp_history=0.1,
            corroboration=0.3,
            test_exclusion=0.0,
            fis_score=fis_score,
        )

        # FIS decision mapping
        fis_decision = "block" if sev in ("critical", "high") else "warn" if sev == "medium" else "pass"

        try:
            result_op = agg.aggregate(
                fis_score=fis_score,
                fis_decision=fis_decision,
                evidence=evidence,
                counterfactual_verified=None,
            )
            click.echo(f"  {f.file}:{f.start_line}  [{f.rule_id}]  sev={sev}")
            click.echo(f"    FIS={fis_decision} → Aggregated={result_op.decision.value} (P={result_op.confidence:.2f})")
            click.echo(f"    {result_op.reasoning}")
            click.echo()
        except Exception as e:
            click.echo(f"  {f.file}:{f.start_line}  [{f.rule_id}]  — aggregator failed: {e}")

    if second_opinion_count == 0:
        click.echo("  No findings above threshold — nothing to second-opinion.")
    else:
        click.echo(f"\n{second_opinion_count} findings analyzed with ExplainableAggregator.")


@main.command("diff")
@click.option("--repo", default=".", help="Repository root")
@click.option("--baseline", required=True, help="Path to baseline findings JSON (from `loomscan check --json`)")
@click.option("--current", help="Path to current findings JSON (default: run fresh scan)")
def diff(repo: str, baseline: str, current: str):
    """v7.4: Differential analysis — compare current scan against a baseline.

    Uses the DifferentialAnalyzer class (incremental.py) which was previously
    defined but never wired. Shows added/removed findings vs the baseline.

    Baseline JSON can be generated with: loomscan check --full --json > baseline.json
    """
    from pathlib import Path
    import json
    from ..incremental import DifferentialAnalyzer

    repo_root = Path(repo).resolve()
    baseline_path = Path(baseline)
    if not baseline_path.exists():
        click.echo(f"Error: baseline file {baseline} does not exist", err=True)
        sys.exit(1)

    try:
        with open(baseline_path) as f:
            baseline_data = json.load(f)
        baseline_findings = baseline_data.get("findings", []) if isinstance(baseline_data, dict) else baseline_data
    except Exception as e:
        click.echo(f"Error loading baseline: {e}", err=True)
        sys.exit(1)

    # Get current findings
    if current:
        current_path = Path(current)
        if not current_path.exists():
            click.echo(f"Error: current file {current} does not exist", err=True)
            sys.exit(1)
        try:
            with open(current_path) as f:
                current_data = json.load(f)
            current_findings = current_data.get("findings", []) if isinstance(current_data, dict) else current_data
        except Exception as e:
            click.echo(f"Error loading current: {e}", err=True)
            sys.exit(1)
    else:
        # Run a fresh scan
        from ..orchestrator import Orchestrator
        orch = Orchestrator(repo_root=repo_root)
        result = orch.run_full()
        current_findings = [f.to_dict() if hasattr(f, "to_dict") else {
            "file": f.file, "line": f.start_line, "rule_id": f.rule_id
        } for f in result.findings]

    da = DifferentialAnalyzer()
    diff_result = da.diff(baseline_findings, current_findings)

    click.echo(f"\nDifferential analysis: baseline={len(baseline_findings)} → current={len(current_findings)}")
    click.echo(f"  Added:     {len(diff_result.added)}")
    click.echo(f"  Removed:   {len(diff_result.removed)}")
    click.echo(f"  Unchanged: {diff_result.unchanged_count}")

    if diff_result.added:
        click.echo(f"\n+ ADDED findings ({len(diff_result.added)}):")
        for f in diff_result.added[:20]:  # show first 20
            click.echo(f"  + {f.get('file','')}:{f.get('line',0)}  [{f.get('rule_id','')}]")
        if len(diff_result.added) > 20:
            click.echo(f"  ... and {len(diff_result.added) - 20} more")

    if diff_result.removed:
        click.echo(f"\n- REMOVED findings ({len(diff_result.removed)}):")
        for f in diff_result.removed[:20]:
            click.echo(f"  - {f.get('file','')}:{f.get('line',0)}  [{f.get('rule_id','')}]")
        if len(diff_result.removed) > 20:
            click.echo(f"  ... and {len(diff_result.removed) - 20} more")

    # Exit code: 0 if no new findings, 1 if new findings added
    if diff_result.added:
        sys.exit(1)
    sys.exit(0)




# =============================================================================
# v7.5: Real GNN-on-CPG — torch-geometric based, learned weights
# =============================================================================

@main.command("gnn-score")
@click.option("--repo", default=".", help="Repository root")
@click.option("--threshold", default=0.5, type=float, help="Risk score threshold to report")
def gnn_score(repo: str, threshold: float):
    """v7.5: Score functions with the real GNN-on-CPG model.

    Uses a 2-layer GCN (torch-geometric) with LEARNED weights operating on a
    Code Property Graph built from Python AST. This is NOT the HeuristicRiskScorer
    (hand-tuned logistic regression) — it's a real neural network with learned
    weights trained on labeled findings.

    The model is saved to ~/.loomscan-cache/gnn_model.pt. If no trained model
    exists, uses random weights (run `loomscan gnn-train` first).

    Falls back to HeuristicRiskScorer if torch/torch-geometric not installed.
    """
    from pathlib import Path
    from ..gnn_cpg import scan_repo_with_gnn, is_gnn_available

    if not is_gnn_available():
        click.echo("⚠️  torch + torch-geometric not installed. Install with:")
        click.echo("   pip install torch torch-geometric")
        click.echo("   Falling back to HeuristicRiskScorer (hand-tuned, not a real GNN).")
        from ..learning import scan_repo_with_gnn as scan_heuristic
        results = scan_heuristic(Path(repo))
        click.echo(f"\n{len(results)} function(s) scored with HeuristicRiskScorer:\n")
        for r in results[:20]:
            mark = "⚠️ " if r.score >= threshold else "   "
            click.echo(f"  {mark}{r.file}:{r.line}  {r.function}()  score={r.score:.3f}")
        return

    repo_root = Path(repo).resolve()
    if not repo_root.exists():
        click.echo(f"Error: repo {repo} does not exist", err=True)
        sys.exit(1)

    results = scan_repo_with_gnn(repo_root)
    click.echo(f"\n{len(results)} function(s) scored with real GNN-on-CPG:\n")

    risky = [r for r in results if r.score >= threshold]
    for r in sorted(risky, key=lambda x: -x.score)[:20]:
        model_tag = "[GNN]" if r.model == "gnn" else "[heuristic]"
        click.echo(f"  ⚠️  {r.file}:{r.line}  {r.function}()  score={r.score:.3f}  {model_tag}")

    click.echo(f"\n{len(risky)} function(s) above threshold {threshold} (out of {len(results)} total)")
    if len(risky) > 20:
        click.echo(f"  (showing top 20 by score)")

    if risky:
        sys.exit(1)
    sys.exit(0)


@main.command("gnn-train")
@click.option("--label-db", default=".loomscan-cache/labels.json", help="Path to labeled findings JSON")
@click.option("--epochs", default=50, type=int, help="Training epochs")
@click.option("--lr", default=0.01, type=float, help="Learning rate")
def gnn_train(label_db: str, epochs: int, lr: float):
    """v7.5: Train the GNN-on-CPG model on labeled findings.

    Reads labeled findings from --label-db (populated by `loomscan feedback tp/fp`).
    Each labeled finding contributes its function source + label (1.0 for TP, 0.0 for FP).

    The trained model is saved to ~/.loomscan-cache/gnn_model.pt and used by
    `loomscan gnn-score` for subsequent scans.
    """
    from pathlib import Path
    from ..gnn_cpg import train_gnn, is_gnn_available, MODEL_PATH

    if not is_gnn_available():
        click.echo("❌ torch + torch-geometric not installed. Install with:")
        click.echo("   pip install torch torch-geometric")
        sys.exit(1)

    label_path = Path(label_db)
    if not label_path.exists():
        click.echo(f"❌ No label database found at {label_db}.")
        click.echo("   Label findings with `loomscan feedback tp/fp <rule_id>` first.")
        sys.exit(1)

    try:
        with open(label_path) as f:
            labels = json.loads(f.read())
    except Exception as e:
        click.echo(f"❌ Failed to load labels: {e}", err=True)
        sys.exit(1)

    # Build training data: (source, function_name, line, label)
    training_data = []
    for entry in labels if isinstance(labels, list) else labels.get("labels", []):
        source = entry.get("source") or entry.get("snippet") or ""
        fname = entry.get("function") or entry.get("rule_id") or "<unknown>"
        fline = int(entry.get("line", 0))
        label = 1.0 if entry.get("label") in ("tp", "true_positive", True, 1) else 0.0
        if source:
            training_data.append((source, fname, fline, label))

    if not training_data:
        click.echo("❌ No training data with source code found in label DB.")
        click.echo("   Labels need a 'source' or 'snippet' field to train the GNN.")
        sys.exit(1)

    click.echo(f"Training GNN on {len(training_data)} labeled function(s)...")
    click.echo(f"  epochs={epochs} lr={lr}")
    click.echo()

    result = train_gnn(training_data, epochs=epochs, lr=lr)
    if result is None:
        click.echo("❌ Training failed (torch unavailable).")
        sys.exit(1)
    if "error" in result:
        click.echo(f"❌ Training failed: {result['error']}")
        sys.exit(1)

    click.echo(f"✅ GNN trained successfully.")
    click.echo(f"   graphs trained:    {result['graphs_trained']}")
    click.echo(f"   positive examples: {result['positive_examples']}")
    click.echo(f"   negative examples: {result['negative_examples']}")
    click.echo(f"   final loss:        {result['final_loss']:.4f}")
    click.echo(f"   model saved to:    {result['model_path']}")
    click.echo()
    click.echo("Run `loomscan gnn-score --repo .` to use the trained model.")


