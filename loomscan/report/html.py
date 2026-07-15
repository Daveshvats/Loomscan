"""v5.21: JSON-driven HTML report — Hermes-inspired dark theme with Courier font.

Improvements over v5.20:
  - Courier/monospace font throughout (like Hermes Agent)
  - Fixed padding and spacing issues
  - Proper donut chart rendering with correct SVG math
  - Added code graph visualization section
  - Better card layout with consistent spacing
  - LoomScan ASCII logo in header
"""
from __future__ import annotations

from pathlib import Path
from datetime import datetime
from typing import List
import json
import base64

from ..models import PipelineResult, Finding, Severity, Decision


def save_html(result: PipelineResult, repo_root: Path, output: Path,
              scan_info: dict = None) -> None:
    """Save a JSON-driven HTML report.

    v5.22: scan_info dict contains flags, settings, excludes, file counts
    for display in the HTML overview section.
    """
    json_path = output.parent / "result.json"
    if not json_path.exists():
        result.to_json(json_path)
    html = _generate_html_template(result, repo_root, scan_info)
    output.write_text(html, encoding="utf-8")


def to_html(result: PipelineResult, repo_root: Path,
            scan_info: dict = None) -> str:
    """Generate HTML string (for backward compat)."""
    return _generate_html_template(result, repo_root, scan_info)


def _generate_html_template(result: PipelineResult, repo_root: Path,
                            scan_info: dict = None) -> str:
    """Generate the HTML template with embedded JSON data."""
    findings_data = []
    for f in result.findings:
        findings_data.append({
            "rule_id": f.rule_id,
            "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
            "message": f.message,
            "file": f.file,
            "line": f.start_line,
            "layer": f.layer.value if hasattr(f.layer, 'value') else str(f.layer),
            "confidence": round(f.confidence * 100) if f.confidence else 0,
            "cwe": f.cwe if hasattr(f, 'cwe') else "",
            "fix": f.fix_suggestion if hasattr(f, 'fix_suggestion') and f.fix_suggestion else "",
        })

    by_sev = {}
    for f in result.findings:
        sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
        by_sev[sev] = by_sev.get(sev, 0) + 1

    # Build code graph data (simple dependency graph from findings)
    graph_nodes = set()
    graph_edges = []
    for f in result.findings:
        graph_nodes.add(f.file)
        if hasattr(f, 'cwe') and f.cwe:
            graph_nodes.add(f.cwe)
            graph_edges.append({"source": f.file, "target": f.cwe, "sev": f.severity.value if hasattr(f.severity, 'value') else str(f.severity)})

    scan_data = {
        "version": "5.22.0",
        "timestamp": datetime.now().isoformat(),
        "repo": str(repo_root),
        "total_findings": len(result.findings),
        "decision": result.final_decision.value if hasattr(result.final_decision, 'value') else str(result.final_decision),
        "by_severity": by_sev,
        "findings": findings_data,
        "layers_run": result.layers_run if hasattr(result, 'layers_run') else [],
        "layer_timings": result.layer_timings if hasattr(result, 'layer_timings') else {},
        "graph": {"nodes": list(graph_nodes)[:200], "edges": graph_edges[:500]},
        # v5.22: Scan configuration info for the overview section
        "scan_info": scan_info or {},
    }

    json_b64 = base64.b64encode(json.dumps(scan_data).encode('utf-8')).decode('ascii')
    return _HTML_TEMPLATE.replace("__SCAN_DATA_B64__", json_b64)


_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LoomScan Report</title>
<style>
:root {
  --bg: #0a0e14;
  --bg2: #0f1419;
  --card: #151a21;
  --card2: #1a1f28;
  --border: #252b35;
  --border2: #2d3440;
  --text: #c9d1d9;
  --dim: #6e7681;
  --accent: #58a6ff;
  --crit: #f85149;
  --high: #ff7b72;
  --med: #d29922;
  --low: #58a6ff;
  --info: #6e7681;
  --pass: #3fb950;
  --warn: #d29922;
  --block: #f85149;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  background: var(--bg); color: var(--text);
  font-family: 'Courier New', Courier, monospace;
  font-size: 13px; line-height: 1.5;
}
.app { display: flex; min-height: 100vh; }
.sidebar {
  width: 200px; background: var(--bg2);
  border-right: 1px solid var(--border);
  padding: 0; flex-shrink: 0;
}
.sidebar-logo {
  padding: 20px; border-bottom: 1px solid var(--border);
  text-align: center;
}
.sidebar-logo .logo-text {
  color: var(--accent); font-weight: bold; font-size: 16px;
}
.sidebar-logo .logo-ver {
  color: var(--dim); font-size: 11px; margin-top: 4px;
}
.sidebar nav { padding: 12px 0; }
.sidebar nav a {
  display: block; padding: 8px 20px;
  color: var(--dim); text-decoration: none;
  font-size: 12px; transition: all 0.15s;
  border-left: 2px solid transparent;
}
.sidebar nav a:hover {
  color: var(--text); background: var(--card);
  border-left-color: var(--accent);
}
.sidebar nav a.active {
  color: var(--text); background: var(--card);
  border-left-color: var(--accent);
}
.main { flex: 1; padding: 32px 40px; overflow-x: auto; max-width: calc(100vw - 200px); }
.header {
  display: flex; justify-content: space-between;
  align-items: center; margin-bottom: 24px;
}
.header h1 {
  font-size: 22px; font-weight: normal;
  color: var(--text);
}
.header h1 .accent { color: var(--accent); }
.badge {
  padding: 4px 14px; border-radius: 4px;
  font-size: 11px; font-weight: bold;
  text-transform: uppercase; letter-spacing: 1px;
}
.badge.pass { background: rgba(63,185,80,0.15); color: var(--pass); border: 1px solid rgba(63,185,80,0.3); }
.badge.warn { background: rgba(210,153,34,0.15); color: var(--warn); border: 1px solid rgba(210,153,34,0.3); }
.badge.block { background: rgba(248,81,73,0.15); color: var(--block); border: 1px solid rgba(248,81,73,0.3); }
.meta {
  color: var(--dim); font-size: 12px;
  margin-bottom: 28px; padding: 12px 16px;
  background: var(--card2); border-radius: 6px;
  border: 1px solid var(--border);
}
.meta span { margin-right: 24px; }
.meta span strong { color: var(--text); font-weight: normal; }
.cards {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
  gap: 12px; margin-bottom: 28px;
}
.card {
  background: var(--card); border: 1px solid var(--border);
  border-radius: 8px; padding: 16px 18px;
  transition: border-color 0.15s;
}
.card:hover { border-color: var(--border2); }
.card .label {
  color: var(--dim); font-size: 10px;
  text-transform: uppercase; letter-spacing: 1px;
  margin-bottom: 8px;
}
.card .value { font-size: 28px; font-weight: bold; }
.card.crit { border-left: 3px solid var(--crit); }
.card.crit .value { color: var(--crit); }
.card.high { border-left: 3px solid var(--high); }
.card.high .value { color: var(--high); }
.card.med { border-left: 3px solid var(--med); }
.card.med .value { color: var(--med); }
.card.low { border-left: 3px solid var(--low); }
.card.low .value { color: var(--low); }
.card.info { border-left: 3px solid var(--info); }
.card.info .value { color: var(--info); }
.card.total { border-left: 3px solid var(--accent); }
.card.total .value { color: var(--text); }
.row { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 28px; }
.panel {
  background: var(--card); border: 1px solid var(--border);
  border-radius: 8px; padding: 20px;
}
.panel h3 {
  color: var(--dim); font-size: 11px;
  text-transform: uppercase; letter-spacing: 1px;
  margin-bottom: 16px; font-weight: normal;
}
/* Donut chart */
.donut-container { display: flex; align-items: center; justify-content: center; gap: 24px; }
.donut { position: relative; width: 140px; height: 140px; }
.donut svg { width: 140px; height: 140px; transform: rotate(-90deg); }
.donut .center {
  position: absolute; top: 50%; left: 50%;
  transform: translate(-50%, -50%);
  text-align: center;
}
.donut .center .num { font-size: 28px; font-weight: bold; color: var(--text); }
.donut .center .txt { font-size: 10px; color: var(--dim); text-transform: uppercase; }
.legend { display: flex; flex-direction: column; gap: 6px; }
.legend-item { display: flex; align-items: center; gap: 8px; font-size: 12px; }
.legend-dot { width: 8px; height: 8px; border-radius: 2px; }
.legend-val { color: var(--dim); margin-left: auto; }
/* Details panel */
.details-list { line-height: 2.2; }
.details-list .row-item { display: flex; justify-content: space-between; }
.details-list .row-item .key { color: var(--dim); }
.details-list .row-item .val { color: var(--text); }
/* Filters */
.filters { display: flex; gap: 10px; margin-bottom: 16px; flex-wrap: wrap; }
.filters input, .filters select {
  background: var(--card); border: 1px solid var(--border);
  color: var(--text); padding: 8px 12px;
  border-radius: 6px; font-size: 12px;
  font-family: inherit;
}
.filters input { flex: 1; min-width: 200px; }
.filters input:focus, .filters select:focus { outline: none; border-color: var(--accent); }
/* Table */
.table-wrap { background: var(--card); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
table { width: 100%; border-collapse: collapse; }
th {
  background: var(--card2); padding: 10px 14px;
  text-align: left; font-size: 10px;
  text-transform: uppercase; letter-spacing: 1px;
  color: var(--dim); font-weight: normal;
  border-bottom: 1px solid var(--border);
}
td { padding: 10px 14px; border-bottom: 1px solid var(--border); font-size: 12px; }
tr:last-child td { border-bottom: none; }
tr:hover { background: rgba(255,255,255,0.02); }
.sev {
  padding: 2px 8px; border-radius: 3px;
  font-size: 10px; font-weight: bold;
  text-transform: uppercase;
}
.sev.critical { background: rgba(248,81,73,0.15); color: var(--crit); }
.sev.high { background: rgba(255,123,114,0.15); color: var(--high); }
.sev.medium { background: rgba(210,153,34,0.15); color: var(--med); }
.sev.low { background: rgba(88,166,255,0.15); color: var(--low); }
.sev.info { background: rgba(110,118,129,0.15); color: var(--info); }
.fix { color: var(--pass); font-size: 11px; margin-top: 4px; padding-left: 12px; border-left: 2px solid rgba(63,185,80,0.3); }
.file-path { color: var(--dim); font-size: 11px; }
.rule-id { color: var(--accent); font-size: 11px; }
.cwe-badge { color: var(--dim); font-size: 11px; }
/* Pagination */
.pagination { display: flex; justify-content: center; gap: 6px; margin-top: 16px; }
.pagination button {
  background: var(--card); border: 1px solid var(--border);
  color: var(--text); padding: 4px 10px;
  border-radius: 4px; cursor: pointer;
  font-family: inherit; font-size: 11px;
}
.pagination button.active { background: var(--accent); border-color: var(--accent); color: #000; }
.pagination button:disabled { opacity: 0.3; cursor: default; }
/* Graph */
.graph-container { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; min-height: 400px; position: relative; overflow: hidden; }
.graph-svg { width: 100%; height: 400px; }
.graph-node { fill: var(--accent); }
.graph-node.crit { fill: var(--crit); }
.graph-node.high { fill: var(--high); }
.graph-node.med { fill: var(--med); }
.graph-edge { stroke: var(--border2); stroke-width: 1; }
.graph-label { fill: var(--dim); font-size: 9px; font-family: inherit; }
.hidden { display: none; }
</style>
</head>
<body>
<div class="app">
  <div class="sidebar">
    <div class="sidebar-logo">
      <div class="logo-text">🕷️ LOOMSCAN</div>
      <div class="logo-ver" id="ver">v5.21</div>
    </div>
    <nav>
      <a href="#" class="active" onclick="showSection('overview', this)">▸ Overview</a>
      <a href="#" onclick="showSection('findings', this)">▸ Findings</a>
      <a href="#" onclick="showSection('graph', this)">▸ Code Graph</a>
      <a href="#" onclick="exportData('json')">▸ Export JSON</a>
      <a href="#" onclick="exportData('sarif')">▸ Export SARIF</a>
    </nav>
  </div>
  <div class="main">
    <div class="header">
      <h1><span class="accent">LoomScan</span> Report</h1>
      <span id="decision-badge" class="badge pass">PASS</span>
    </div>
    <div class="meta" id="meta"></div>

    <!-- Overview -->
    <div id="overview-section">
      <div class="cards" id="cards"></div>
      <div class="row">
        <div class="panel">
          <h3>Severity Distribution</h3>
          <div class="donut-container">
            <div class="donut" id="donut"></div>
            <div class="legend" id="legend"></div>
          </div>
        </div>
        <div class="panel">
          <h3>Scan Details</h3>
          <div class="details-list" id="details"></div>
        </div>
      </div>
    </div>

    <!-- Findings -->
    <div id="findings-section" class="hidden">
      <div class="filters">
        <input type="text" id="search" placeholder="Search findings..." oninput="renderTable()">
        <select id="filter-sev" onchange="renderTable()">
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
        <select id="filter-layer" onchange="renderTable()"></select>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>#</th><th>Sev</th><th>Rule</th><th>File</th><th>Line</th><th>Message</th><th>CWE</th></tr></thead>
          <tbody id="tbody"></tbody>
        </table>
      </div>
      <div class="pagination" id="pagination"></div>
    </div>

    <!-- Code Graph -->
    <div id="graph-section" class="hidden">
      <div class="panel">
        <h3>Code Dependency Graph (File → CWE)</h3>
        <div class="graph-container">
          <svg class="graph-svg" id="graph-svg"></svg>
        </div>
        <p style="color:var(--dim);font-size:11px;margin-top:12px;">
          Nodes: files (blue) and CWEs (colored by max severity). Edges: finding connects file to CWE.
        </p>
      </div>
    </div>
  </div>
</div>
<script>
const data = JSON.parse(atob("__SCAN_DATA_B64__"));
let currentPage = 1;
const perPage = 50;

function init() {
  const sev = data.by_severity;
  const total = data.total_findings;
  document.getElementById('ver').textContent = 'v' + data.version;
  document.getElementById('decision-badge').textContent = data.decision.toUpperCase();
  const badge = document.getElementById('decision-badge');
  badge.className = 'badge ' + (data.decision === 'pass' ? 'pass' : data.decision === 'warn' ? 'warn' : 'block');
  document.getElementById('meta').innerHTML =
    '<span><strong>Date:</strong> ' + new Date(data.timestamp).toLocaleString() + '</span>' +
    '<span><strong>Repo:</strong> ' + data.repo + '</span>' +
    '<span><strong>Findings:</strong> ' + total + '</span>' +
    '<span><strong>Layers:</strong> ' + (data.layers_run||[]).length + '</span>';

  // Cards
  const cards = [
    {cls:'crit',label:'Critical',val:sev.critical||0},
    {cls:'high',label:'High',val:sev.high||0},
    {cls:'med',label:'Medium',val:sev.medium||0},
    {cls:'low',label:'Low',val:sev.low||0},
    {cls:'info',label:'Info',val:sev.info||0},
    {cls:'total',label:'Total',val:total},
  ];
  document.getElementById('cards').innerHTML = cards.map(c =>
    `<div class="card ${c.cls}"><div class="label">${c.label}</div><div class="value">${c.val}</div></div>`
  ).join('');

  // Donut chart
  const colors = {critical:'#f85149', high:'#ff7b72', medium:'#d29922', low:'#58a6ff', info:'#6e7681'};
  const sevOrder = ['critical','high','medium','low','info'];
  const sevLabels = {critical:'Critical', high:'High', medium:'Medium', low:'Low', info:'Info'};
  const r = 55, circumference = 2 * Math.PI * r;
  let offset = 0;
  let svg = `<svg viewBox="0 0 140 140"><circle cx="70" cy="70" r="${r}" fill="none" stroke="var(--border)" stroke-width="16"/>`;
  sevOrder.forEach(s => {
    const val = sev[s] || 0;
    if (val > 0) {
      const pct = val / total;
      const dashLen = pct * circumference;
      svg += `<circle cx="70" cy="70" r="${r}" fill="none" stroke="${colors[s]}" stroke-width="16" stroke-dasharray="${dashLen} ${circumference - dashLen}" stroke-dashoffset="${-offset}"/>`;
      offset += dashLen;
    }
  });
  svg += '</svg>';
  document.getElementById('donut').innerHTML = `<div class="donut">${svg}<div class="center"><div class="num">${total}</div><div class="txt">Findings</div></div></div>`;

  // Legend
  document.getElementById('legend').innerHTML = sevOrder.map(s => {
    const val = sev[s] || 0;
    return `<div class="legend-item"><div class="legend-dot" style="background:${colors[s]}"></div>${sevLabels[s]}<span class="legend-val">${val}</span></div>`;
  }).join('');

  // Details
  const layers = data.layers_run || [];
  const timings = data.layer_timings || {};
  const si = data.scan_info || {};
  let detailsHtml = '';
  // v5.22: Scan configuration info
  detailsHtml += `<div class="row-item"><span class="key">━━ Scan Config ━━</span><span class="val"></span></div>`;
  if (si.command) detailsHtml += `<div class="row-item"><span class="key">Command</span><span class="val">${si.command}</span></div>`;
  if (si.engine) detailsHtml += `<div class="row-item"><span class="key">Engine</span><span class="val">${si.engine}</span></div>`;
  if (si.strictness) detailsHtml += `<div class="row-item"><span class="key">Strictness</span><span class="val">${si.strictness}/9</span></div>`;
  if (si.repo) detailsHtml += `<div class="row-item"><span class="key">Repository</span><span class="val" style="font-size:11px">${si.repo}</span></div>`;
  if (si.total_files !== undefined) detailsHtml += `<div class="row-item"><span class="key">Files scanned</span><span class="val">${si.total_files}</span></div>`;
  if (si.excluded_files !== undefined) detailsHtml += `<div class="row-item"><span class="key">Files excluded</span><span class="val">${si.excluded_files}</span></div>`;
  if (si.excluded_folders !== undefined) detailsHtml += `<div class="row-item"><span class="key">Folders excluded</span><span class="val">${si.excluded_folders}</span></div>`;
  if (si.excludes && si.excludes.length) detailsHtml += `<div class="row-item"><span class="key">CLI excludes</span><span class="val" style="font-size:11px">${si.excludes.join(', ')}</span></div>`;
  if (si.modules && si.modules.length) detailsHtml += `<div class="row-item"><span class="key">Modules active</span><span class="val">${si.modules.length}/18</span></div>`;
  detailsHtml += `<div class="row-item"><span class="key">━━ Results ━━</span><span class="val"></span></div>`;
  detailsHtml += `<div class="row-item"><span class="key">Decision</span><span class="val">${data.decision.toUpperCase()}</span></div>`;
  detailsHtml += `<div class="row-item"><span class="key">Total findings</span><span class="val">${total}</span></div>`;
  detailsHtml += `<div class="row-item"><span class="key">Critical</span><span class="val" style="color:${colors.critical}">${sev.critical||0}</span></div>`;
  detailsHtml += `<div class="row-item"><span class="key">High</span><span class="val" style="color:${colors.high}">${sev.high||0}</span></div>`;
  detailsHtml += `<div class="row-item"><span class="key">Medium</span><span class="val" style="color:${colors.medium}">${sev.medium||0}</span></div>`;
  detailsHtml += `<div class="row-item"><span class="key">Low</span><span class="val" style="color:${colors.low}">${sev.low||0}</span></div>`;
  detailsHtml += `<div class="row-item"><span class="key">Info</span><span class="val" style="color:${colors.info}">${sev.info||0}</span></div>`;
  detailsHtml += `<div class="row-item"><span class="key">Layers run</span><span class="val">${layers.length}</span></div>`;
  document.getElementById('details').innerHTML = detailsHtml;

  // Layer filter
  const layerSet = [...new Set(data.findings.map(f=>f.layer))];
  document.getElementById('filter-layer').innerHTML = '<option value="">All Layers</option>' +
    layerSet.map(l=>`<option value="${l}">${l}</option>`).join('');

  renderTable();
  renderGraph();
}

function renderTable() {
  const search = document.getElementById('search').value.toLowerCase();
  const filterSev = document.getElementById('filter-sev').value;
  const filterLayer = document.getElementById('filter-layer').value;
  let filtered = data.findings.filter(f => {
    if (filterSev && f.severity !== filterSev) return false;
    if (filterLayer && f.layer !== filterLayer) return false;
    if (search && !f.message.toLowerCase().includes(search) && !f.rule_id.toLowerCase().includes(search) && !f.file.toLowerCase().includes(search)) return false;
    return true;
  });
  const totalPages = Math.ceil(filtered.length / perPage);
  if (currentPage > totalPages) currentPage = 1;
  const start = (currentPage - 1) * perPage;
  const pageItems = filtered.slice(start, start + perPage);
  document.getElementById('tbody').innerHTML = pageItems.map((f,i) => {
    const num = start + i + 1;
    const fileShort = f.file.length > 45 ? '...' + f.file.substring(f.file.length - 42) : f.file;
    const ruleShort = f.rule_id.length > 28 ? f.rule_id.substring(0, 25) + '...' : f.rule_id;
    const msgShort = f.message.length > 70 ? f.message.substring(0, 67) + '...' : f.message;
    return `<tr>
      <td>${num}</td>
      <td><span class="sev ${f.severity}">${f.severity}</span></td>
      <td class="rule-id" title="${f.rule_id}">${ruleShort}</td>
      <td class="file-path" title="${f.file}">${fileShort}</td>
      <td>${f.line}</td>
      <td>${msgShort}${f.fix ? `<div class="fix">${f.fix}</div>` : ''}</td>
      <td class="cwe-badge">${f.cwe || ''}</td>
    </tr>`;
  }).join('') || '<tr><td colspan="7" style="text-align:center;padding:40px;color:var(--dim)">No findings match filters</td></tr>';

  const pag = document.getElementById('pagination');
  if (totalPages <= 1) { pag.innerHTML = ''; return; }
  let html = `<button onclick="goPage(${currentPage-1})" ${currentPage===1?'disabled':''}>◀</button>`;
  for (let i = 1; i <= Math.min(totalPages, 10); i++)
    html += `<button onclick="goPage(${i})" class="${i===currentPage?'active':''}">${i}</button>`;
  if (totalPages > 10) html += `<button disabled>...</button><button onclick="goPage(${totalPages})" class="${totalPages===currentPage?'active':''}">${totalPages}</button>`;
  html += `<button onclick="goPage(${currentPage+1})" ${currentPage===totalPages?'disabled':''}>▶</button>`;
  pag.innerHTML = html;
}

function goPage(p) { currentPage = p; renderTable(); }

function showSection(name, link) {
  document.querySelectorAll('.sidebar nav a').forEach(a => a.classList.remove('active'));
  link.classList.add('active');
  ['overview','findings','graph'].forEach(s => {
    document.getElementById(s + '-section').classList.toggle('hidden', s !== name);
  });
}

function renderGraph() {
  const g = data.graph || {nodes:[], edges:[]};
  if (!g.nodes.length) return;
  const svg = document.getElementById('graph-svg');
  const w = svg.clientWidth || 800, h = 400;
  // Simple circular layout
  const n = g.nodes.length;
  const cx = w/2, cy = h/2, radius = Math.min(w,h)/2 - 40;
  const positions = {};
  g.nodes.forEach((node, i) => {
    const angle = (i / n) * 2 * Math.PI;
    positions[node] = {x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle)};
  });
  let html = '';
  // Edges
  g.edges.forEach(e => {
    const s = positions[e.source], t = positions[e.target];
    if (s && t) {
      const color = e.sev === 'critical' ? '#f85149' : e.sev === 'high' ? '#ff7b72' :
        e.sev === 'medium' ? '#d29922' : e.sev === 'low' ? '#58a6ff' : '#6e7681';
      html += `<line class="graph-edge" x1="${s.x}" y1="${s.y}" x2="${t.x}" y2="${t.y}" stroke="${color}" stroke-opacity="0.3"/>`;
    }
  });
  // Nodes
  g.nodes.forEach(node => {
    const p = positions[node];
    if (!p) return;
    const isCWE = node.startsWith('CWE-');
    const cls = isCWE ? 'graph-node crit' : 'graph-node';
    const r = isCWE ? 5 : 4;
    const label = node.length > 20 ? node.substring(0,17)+'...' : node;
    html += `<circle class="${cls}" cx="${p.x}" cy="${p.y}" r="${r}"/>`;
    html += `<text class="graph-label" x="${p.x+8}" y="${p.y+3}">${label}</text>`;
  });
  svg.innerHTML = html;
}

function exportData(type) {
  if (type === 'json') {
    const blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'loomscan-report.json'; a.click();
  } else if (type === 'sarif') {
    alert('SARIF file: .loomscan-reports/result.sarif');
  }
}

init();
</script>
</body>
</html>"""
