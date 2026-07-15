"""v6.2: Pre-merge branch analysis — see what happens if you merge.

Scans both base and head branches, diffs the findings, and shows:
  - NEW findings introduced by this branch
  - RESOLVED findings (fixed by this branch)
  - Blast radius of the changes
  - Merge recommendation (approve / request_changes / block)
"""
from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, field

from .models import Finding, Severity, Decision


@dataclass
class MergeReviewResult:
    base_branch: str
    head_branch: str
    changed_files: List[str] = field(default_factory=list)
    new_findings: List[Finding] = field(default_factory=list)
    resolved_findings: List[Finding] = field(default_factory=list)
    existing_findings_count: int = 0
    blast_radius: Dict = field(default_factory=dict)
    recommendation: str = "approve"  # approve | request_changes | block
    summary: str = ""
    scan_time: float = 0.0


def get_changed_files(repo_root: Path, base: str, head: str) -> List[str]:
    result = subprocess.run(
        ["git", "diff", "--name-only", f"{base}..{head}"],
        cwd=repo_root, capture_output=True, text=True, check=False
    )
    return [f.strip() for f in result.stdout.splitlines() if f.strip()]


def run_merge_review(repo_root: Path, base: str, head: str = "HEAD",
                     strictness: int = 7) -> MergeReviewResult:
    """Run a complete pre-merge analysis."""
    t0 = time.perf_counter()

    changed_files = get_changed_files(repo_root, base, head)
    if not changed_files:
        return MergeReviewResult(
            base_branch=base, head_branch=head,
            summary="No files changed between branches.",
            recommendation="approve",
            scan_time=time.perf_counter() - t0,
        )

    from .orchestrator import Orchestrator
    from .config import STCAConfig

    config = STCAConfig.default()
    config.strictness_level = strictness

    # Scan HEAD (what would be merged)
    orch = Orchestrator(repo_root, config, strictness=strictness)
    head_result = orch.run_full()
    head_findings = head_result.findings

    # Scan BASE (current state) — checkout base, scan, restore
    stash_output = subprocess.run(
        ["git", "stash"], cwd=repo_root, capture_output=True, text=True
    )
    had_stash = "No local changes to save" not in stash_output.stdout

    subprocess.run(["git", "checkout", base], cwd=repo_root,
                   capture_output=True, text=True, check=False)

    try:
        base_orch = Orchestrator(repo_root, config, strictness=strictness)
        base_result = base_orch.run_full()
        base_findings = base_result.findings
    finally:
        # Restore head
        subprocess.run(["git", "checkout", "-"], cwd=repo_root,
                       capture_output=True, text=True, check=False)
        if had_stash:
            subprocess.run(["git", "stash", "pop"], cwd=repo_root,
                           capture_output=True, text=True, check=False)

    # Diff findings by fingerprint
    base_fps = {f.fingerprint for f in base_findings}
    head_fps = {f.fingerprint for f in head_findings}

    new_findings = [f for f in head_findings if f.fingerprint not in base_fps]
    resolved_findings = [f for f in base_findings if f.fingerprint not in head_fps]
    existing_count = len(head_findings) - len(new_findings)

    # Filter new findings to those in changed files
    new_in_changed = [f for f in new_findings if f.file in changed_files]

    # Blast radius
    try:
        from .knowledge_graph import DiffImpactAnalyzer, KnowledgeGraphBuilder
        builder = KnowledgeGraphBuilder(repo_root)
        graph = builder.build()
        analyzer = DiffImpactAnalyzer(graph)
        blast = analyzer.analyze_changed_files(changed_files)
    except Exception:
        blast = {"total_blast_radius": 0, "directly_affected": [], "transitively_affected": []}

    # Recommendation
    critical_new = [f for f in new_in_changed if f.severity == Severity.CRITICAL]
    high_new = [f for f in new_in_changed if f.severity == Severity.HIGH]

    if critical_new:
        recommendation = "block"
        summary = f"BLOCK: {len(critical_new)} critical finding(s) introduced by this branch."
    elif len(high_new) >= 3:
        recommendation = "request_changes"
        summary = f"REQUEST CHANGES: {len(high_new)} high-severity findings introduced."
    elif high_new:
        recommendation = "request_changes"
        summary = f"REQUEST CHANGES: {len(high_new)} high-severity finding(s) need review."
    else:
        recommendation = "approve"
        summary = f"APPROVE: No critical/high findings. {len(new_in_changed)} low/info findings."

    elapsed = time.perf_counter() - t0

    return MergeReviewResult(
        base_branch=base, head_branch=head,
        changed_files=changed_files,
        new_findings=new_in_changed,
        resolved_findings=resolved_findings,
        existing_findings_count=existing_count,
        blast_radius=blast,
        recommendation=recommendation,
        summary=summary,
        scan_time=elapsed,
    )


def format_merge_review(result: MergeReviewResult) -> str:
    """Format merge review as Rich console output."""
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.rule import Rule

    output = []

    # Header
    rec_emoji = {"approve": "✅", "request_changes": "🟡", "block": "🔴"}
    rec_color = {"approve": "green", "request_changes": "yellow", "block": "red"}

    output.append(Rule(f"[bold {rec_color[result.recommendation]}]"
                       f"{rec_emoji[result.recommendation]} LoomScan Merge Review"
                       f" — {result.head_branch} → {result.base_branch}[/]"))

    # Summary stats
    stats = Table(show_header=False, box=None, padding=(0, 2))
    stats.add_column(style="dim")
    stats.add_column()
    stats.add_row("📁 Changed files:", str(len(result.changed_files)))
    stats.add_row("🔴 New findings:", str(len(result.new_findings)))
    stats.add_row("🟢 Resolved:", str(len(result.resolved_findings)))
    stats.add_row("⏱️  Scan time:", f"{result.scan_time:.1f}s")
    stats.add_row("📊 Blast radius:", f"{result.blast_radius.get('total_blast_radius', 0)} functions")
    output.append(stats)
    output.append("")

    # Recommendation
    output.append(Panel(
        Text(result.summary, style=f"bold {rec_color[result.recommendation]}"),
        border_style=rec_color[result.recommendation],
    ))
    output.append("")

    # New findings
    if result.new_findings:
        sev_colors = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "dim",
        }
        output.append("[bold]🔴 NEW FINDINGS (introduced by this branch):[/]")
        for i, f in enumerate(result.new_findings, 1):
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            color = sev_colors.get(f.severity, "white")
            output.append(f"  [{color}][{sev.upper()}][/] {f.rule_id}")
            output.append(f"    → {f.message[:100]}")
            output.append(f"    → {f.file}:{f.start_line}")
            if f.fix_suggestion:
                output.append(f"    → 💡 {f.fix_suggestion[:80]}")
        output.append("")

    # Resolved findings
    if result.resolved_findings:
        output.append("[bold green]🟢 RESOLVED FINDINGS (fixed by this branch):[/]")
        for f in result.resolved_findings[:10]:
            output.append(f"  ✅ {f.rule_id} — {f.file}:{f.start_line}")
        if len(result.resolved_findings) > 10:
            output.append(f"  ... and {len(result.resolved_findings) - 10} more")
        output.append("")

    # Existing
    output.append(f"[dim]🟡 EXISTING (not affected): {result.existing_findings_count} findings[/]")
    output.append("")

    # v7.1: Generate HTML report
    try:
        report_dir = Path(".") / ".loomscan-reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        html_path = report_dir / "merge-review.html"
        _generate_merge_review_html(result, html_path)
        output.append(f"[dim]📄 HTML report: {html_path.resolve()}[/]")
    except Exception:
        pass

    return "\n".join(str(line) for line in output)


def _generate_merge_review_html(result: MergeReviewResult, output_path: Path) -> None:
    """Generate an HTML report for the merge review."""
    import base64

    sev_colors = {
        "critical": "#f85149", "high": "#ff7b72", "medium": "#d29922",
        "low": "#58a6ff", "info": "#6e7681"
    }

    findings_data = []
    for f in result.new_findings:
        sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
        findings_data.append({
            "rule_id": f.rule_id,
            "severity": sev,
            "message": f.message,
            "file": f.file,
            "line": f.start_line,
            "fix": f.fix_suggestion or "",
            "cwe": getattr(f, 'cwe', ''),
        })

    resolved_data = []
    for f in result.resolved_findings[:50]:
        sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
        resolved_data.append({
            "rule_id": f.rule_id,
            "file": f.file,
            "line": f.start_line,
        })

    rec_color = {"approve": "#3fb950", "request_changes": "#d29922", "block": "#f85149"}
    rec_emoji = {"approve": "✅", "request_changes": "🟡", "block": "🔴"}

    data = {
        "recommendation": result.recommendation,
        "summary": result.summary,
        "base": result.base_branch,
        "head": result.head_branch,
        "changed_files": result.changed_files,
        "new_findings": findings_data,
        "resolved": resolved_data,
        "existing_count": result.existing_findings_count,
        "scan_time": result.scan_time,
        "blast_radius": result.blast_radius.get("total_blast_radius", 0),
    }

    json_b64 = base64.b64encode(json.dumps(data).encode('utf-8')).decode('ascii')

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>LoomScan Merge Review</title>
<style>
:root {{ --bg:#0a0e14; --card:#151a21; --border:#252b35; --text:#c9d1d9; --dim:#6e7681; --accent:#58a6ff; }}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ background:var(--bg); color:var(--text); font-family:'Courier New',monospace; font-size:13px; padding:20px; }}
h1 {{ color:var(--accent); margin-bottom:10px; }}
.badge {{ padding:4px 14px; border-radius:4px; font-size:12px; font-weight:bold; text-transform:uppercase; display:inline-block; margin-bottom:20px; }}
.badge.block {{ background:rgba(248,81,73,0.15); color:#f85149; border:1px solid rgba(248,81,73,0.3); }}
.badge.request_changes {{ background:rgba(210,153,34,0.15); color:#d29922; border:1px solid rgba(210,153,34,0.3); }}
.badge.approve {{ background:rgba(63,185,80,0.15); color:#3fb950; border:1px solid rgba(63,185,80,0.3); }}
.stats {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:20px; }}
.stat {{ background:var(--card); border:1px solid var(--border); border-radius:8px; padding:16px; }}
.stat .label {{ color:var(--dim); font-size:10px; text-transform:uppercase; margin-bottom:4px; }}
.stat .value {{ font-size:24px; font-weight:bold; }}
.stat.new {{ border-left:3px solid #f85149; }}
.stat.resolved {{ border-left:3px solid #3fb950; }}
.stat.existing {{ border-left:3px solid #d29922; }}
.stat.time {{ border-left:3px solid var(--accent); }}
table {{ width:100%; border-collapse:collapse; margin-top:12px; background:var(--card); border-radius:8px; overflow:hidden; }}
th {{ background:#1a1f28; padding:10px; text-align:left; font-size:10px; text-transform:uppercase; color:var(--dim); border-bottom:1px solid var(--border); }}
td {{ padding:10px; border-bottom:1px solid var(--border); font-size:12px; }}
.sev {{ padding:2px 8px; border-radius:3px; font-size:10px; font-weight:bold; text-transform:uppercase; }}
.sev.critical {{ background:rgba(248,81,73,0.15); color:#f85149; }}
.sev.high {{ background:rgba(255,123,114,0.15); color:#ff7b72; }}
.sev.medium {{ background:rgba(210,153,34,0.15); color:#d29922; }}
.sev.low {{ background:rgba(88,166,255,0.15); color:#58a6ff; }}
.sev.info {{ background:rgba(110,118,129,0.15); color:#6e7681; }}
.fix {{ color:#3fb950; font-size:11px; margin-top:4px; }}
.section {{ margin-top:20px; }}
.section h2 {{ color:var(--accent); font-size:16px; margin-bottom:8px; }}
</style></head><body>
<h1>🕷️ LoomScan Merge Review</h1>
<div style="color:var(--dim);margin-bottom:10px;">{result.head_branch} → {result.base_branch}</div>
<div id="badge" class="badge {result.recommendation}">{rec_emoji[result.recommendation]} {result.recommendation.upper()}</div>
<div style="margin-bottom:20px;color:var(--text);">{result.summary}</div>

<div class="stats">
<div class="stat new"><div class="label">New Findings</div><div class="value" style="color:#f85149">{len(result.new_findings)}</div></div>
<div class="stat resolved"><div class="label">Resolved</div><div class="value" style="color:#3fb950">{len(result.resolved_findings)}</div></div>
<div class="stat existing"><div class="label">Existing</div><div class="value" style="color:#d29922">{result.existing_findings_count}</div></div>
<div class="stat time"><div class="label">Scan Time</div><div class="value">{result.scan_time:.1f}s</div></div>
</div>

<div class="section">
<h2>🔴 New Findings ({len(result.new_findings)})</h2>
<table>
<tr><th>#</th><th>Sev</th><th>Rule</th><th>File</th><th>Line</th><th>Message</th><th>Fix</th></tr>
<tbody id="new-tbody"></tbody>
</table>
</div>

<div class="section">
<h2>🟢 Resolved ({len(result.resolved_findings)})</h2>
<table>
<tr><th>Rule</th><th>File</th><th>Line</th></tr>
<tbody id="resolved-tbody"></tbody>
</table>
</div>

<script>
const data = JSON.parse(atob("{json_b64}"));
const newTbody = document.getElementById('new-tbody');
data.new_findings.forEach((f,i) => {{
  const tr = document.createElement('tr');
  tr.innerHTML = `<td>${{i+1}}</td><td><span class="sev ${{f.severity}}">${{f.severity}}</span></td>
    <td style="color:#58a6ff">${{f.rule_id}}</td><td style="color:#6e7681;font-size:11px">${{f.file}}</td>
    <td>${{f.line}}</td><td>${{f.message.substring(0,80)}}${{f.fix ? '<div class=\"fix\">💡 '+f.fix.substring(0,60)+'</div>' : ''}}</td>
    <td>${{f.cwe || ''}}</td>`;
  newTbody.appendChild(tr);
}});
const resTbody = document.getElementById('resolved-tbody');
data.resolved.forEach(f => {{
  const tr = document.createElement('tr');
  tr.innerHTML = `<td style="color:#3fb950">✅ ${{f.rule_id}}</td><td style="color:#6e7681;font-size:11px">${{f.file}}</td><td>${{f.line}}</td>`;
  resTbody.appendChild(tr);
}});
</script>
</body></html>"""

    output_path.write_text(html, encoding='utf-8')
