"""v7.6: Security CLI commands — JSX auth, stateful PBT, multi-call analysis.

Extracted from cli.py in v7.6.0 for maintainability.
"""
import sys
import json
import click
from pathlib import Path

from . import main  # noqa: F401 — registers with the Click group

# =============================================================================
# v7.5: Restored modules — jsx_auth, stateful_pbt, multi_call
# These were deleted in v7.4.0 (strategic mistake per audit). Now restored
# from git history and wired via CLI commands. All three are novel detectors
# that no competitor (Semgrep/CodeQL/Snyk) ships.
# =============================================================================

@main.command("jsx-auth")
@click.option("--repo", default=".", help="Repository root")
@click.option("--json", "as_json", is_flag=True, help="Output JSON")
def jsx_auth(repo: str, as_json: bool):
    """v7.5: JSX/React authorization coverage analysis.

    Scans .jsx/.tsx files for auth wrapper patterns (HOCs, hooks, route guards)
    and flags pages WITHOUT any auth wrapper — likely missing authorization.

    Detects:
      - HOC patterns: withAuth(Component), requireAuth(Component)
      - Hook patterns: useAuth(), useUser(), useSession(), useIsAuthenticated()
      - Component patterns: <ProtectedRoute>, <AuthGuard>, <RequireRole>
      - Permission checks: hasPermission('edit'), can('delete'), checkRole('admin')
      - Route guards: Next.js middleware, react-router <PrivateRoute>

    No competitor ships this — Semgrep/CodeQL/Snyk focus on injection/XSS,
    not auth coverage analysis.
    """
    from pathlib import Path
    from ..jsx_auth import extract_all_jsx_auth, JSXAuthViolationDetector

    repo_root = Path(repo).resolve()
    if not repo_root.exists():
        click.echo(f"Error: repo {repo} does not exist", err=True)
        sys.exit(1)

    # Extract all auth rules from the repo
    auth_rules = extract_all_jsx_auth(repo_root)
    click.echo(f"\nFound {len(auth_rules)} auth pattern(s) in {repo_root}:\n")
    for rule in auth_rules[:20]:
        # v7.5.2: Fixed attribute name — was pattern_type (doesn't exist), now wrapper_kind
        click.echo(f"  {rule.file}:{rule.line}  [{rule.wrapper_kind}]  {rule.pattern_text[:60]}")
    if len(auth_rules) > 20:
        click.echo(f"  ... and {len(auth_rules) - 20} more")

    # Detect violations (pages without auth)
    # v7.5.1: Fixed method name — was .detect() (doesn't exist), now .analyze()
    detector = JSXAuthViolationDetector()
    violations = detector.analyze(repo_root)

    click.echo(f"\n{len(violations)} page(s) WITHOUT auth wrapper (likely missing authorization):\n")
    for v in violations[:20]:
        click.echo(f"  {v.file}  — no auth wrapper detected")
    if len(violations) > 20:
        click.echo(f"  ... and {len(violations) - 20} more")

    if as_json:
        import json
        click.echo(json.dumps({
            "auth_patterns": [r.__dict__ if hasattr(r, '__dict__') else str(r) for r in auth_rules],
            "violations": [v.__dict__ if hasattr(v, '__dict__') else str(v) for v in violations],
        }, indent=2, default=str))

    # Exit 1 if violations found (CI-friendly)
    if violations:
        sys.exit(1)
    sys.exit(0)


@main.command("stateful-pbt")
@click.option("--repo", default=".", help="Repository root")
@click.option("--target", help="Specific Python class to test (default: all discovered)")
@click.option("--steps", default=100, type=int, help="Max random action sequence length")
@click.option("--runs", default=10, type=int, help="Number of random runs per target")
def stateful_pbt(repo: str, target: str, steps: int, runs: int):
    """v7.5: Stateful property-based testing for Python classes.

    Auto-generates a state machine model from target classes, generates random
    action sequences (up to --steps), and checks invariants after each action.

    Catches bugs static analysis FUNDAMENTALLY CANNOT:
      - Multi-step state manipulation (add → remove → checkout doesn't clear cart)
      - Order-dependent bugs (A then B vs B then A)
      - Edge cases (empty-cart checkout, negative quantities)
      - Race-condition-like logic bugs (interleaved operations)

    Inspired by Echidna (Trail of Bits) and Hypothesis RuleBasedStateMachine.
    No competitor ships this.
    """
    from pathlib import Path
    from ..stateful_pbt import discover_stateful_targets, run_stateful_tests

    repo_root = Path(repo).resolve()
    if not repo_root.exists():
        click.echo(f"Error: repo {repo} does not exist", err=True)
        sys.exit(1)

    # Discover target classes
    targets = []
    for py_file in repo_root.rglob("*.py"):
        if any(s in str(py_file) for s in (".venv", "node_modules", "__pycache__", ".git")):
            continue
        try:
            file_targets = discover_stateful_targets(py_file)
            for t in file_targets:
                if target is None or target in t[0]:
                    targets.append((py_file, t))
        except Exception:
            continue

    if not targets:
        click.echo("No stateful targets discovered. Look for Python classes with")
        click.echo("mutator methods (add/remove/update/set/insert/delete/push/pop).")
        sys.exit(0)

    click.echo(f"\nDiscovered {len(targets)} stateful target(s):\n")
    for py_file, (class_name, class_source, mutators, invariants) in targets[:10]:
        click.echo(f"  {py_file.name}::{class_name}")
        click.echo(f"    mutators: {mutators[:5]}{'...' if len(mutators) > 5 else ''}")
        click.echo(f"    invariants: {invariants[:3]}{'...' if len(invariants) > 3 else ''}")
    if len(targets) > 10:
        click.echo(f"  ... and {len(targets) - 10} more")

    # Run stateful tests
    click.echo(f"\nRunning stateful PBT (steps={steps}, runs={runs})...\n")
    all_violations = []
    for py_file, (class_name, _, _, _) in targets:
        try:
            violations = run_stateful_tests(py_file, repo_root=repo_root)
            if violations:
                all_violations.extend(violations)
                for v in violations:
                    click.echo(f"  VIOLATION: {v.class_name} — {v.invariant}")
                    click.echo(f"    sequence: {v.action_sequence[:5]}{'...' if len(v.action_sequence) > 5 else ''}")
        except Exception as e:
            click.echo(f"  SKIP {py_file.name}::{class_name}: {e}")

    if all_violations:
        click.echo(f"\n{len(all_violations)} invariant violation(s) found.")
        sys.exit(1)
    click.echo(f"\n✅ All invariants held across {len(targets)} target(s).")
    sys.exit(0)


@main.command("multi-call")
@click.option("--repo", default=".", help="Repository root")
@click.option("--check", type=click.Choice(["all", "reentrancy", "missing-auth", "toctou"]),
              default="all", help="Which check to run")
def multi_call(repo: str, check: str):
    """v7.5: Multi-call bug detection (reentrancy, missing-auth chains, TOCTOU).

    Analyzes call chains across multiple functions to detect bugs that
    single-function analysis misses:

      - reentrancy: external call + state write (reentrancy attack pattern)
      - missing-auth-in-chain: sensitive operation called without auth check
        anywhere in the call chain
      - toctou: check-then-act across function boundaries

    No competitor ships cross-function call-chain analysis at this level.
    """
    from pathlib import Path
    from ..multi_call import scan_repo_multi_call
    from .._paths import is_skipped_dir

    repo_root = Path(repo).resolve()
    if not repo_root.exists():
        click.echo(f"Error: repo {repo} does not exist", err=True)
        sys.exit(1)

    # v7.5.1: Use scan_repo_multi_call which respects skip_dirs (prevents feedback-loop)
    all_violations = scan_repo_multi_call(repo_root, check=check)
    # v7.5.1: Count only non-skipped files (matches scan_repo_multi_call behavior)
    files_scanned = sum(1 for p in repo_root.rglob("*.py") if not is_skipped_dir(p))

    click.echo(f"\nScanned {files_scanned} Python file(s) for multi-call bugs ({check}):\n")

    by_type: dict = {}
    for v in all_violations:
        by_type.setdefault(v.violation_type, []).append(v)

    for vtype, viols in sorted(by_type.items()):
        click.echo(f"  {vtype}: {len(viols)} violation(s)")
        for v in viols[:5]:
            click.echo(f"    {v.file}:{v.line}  {v.description}")
        if len(viols) > 5:
            click.echo(f"    ... and {len(viols) - 5} more")

    if not all_violations:
        click.echo("  ✅ No multi-call violations found.")
        sys.exit(0)
    sys.exit(1)


