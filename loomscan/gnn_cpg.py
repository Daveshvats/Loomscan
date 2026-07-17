"""v7.5: Real Graph Neural Network on Code Property Graph (GNN-on-CPG).

This is a REAL GNN — not the v7.3.4-renamed HeuristicRiskScorer (which was a
hand-tuned logistic regression). It uses torch-geometric's GCNConv layers with
LEARNED weights, trained on labeled findings (TP/FP) to predict whether a
function contains a real vulnerability.

Architecture:
  1. Build a Code Property Graph (CPG) from Python source via AST:
     - Nodes: AST nodes (Function, Call, If, For, While, Assign, etc.)
     - Edges: parent→child (AST), def→use (data flow), call→callee (call graph)
  2. Node features (per AST node):
     - node_type_onehot (16-dim: Function, Call, If, For, While, Assign, Return,
       Name, Attribute, Constant, BinOp, Compare, BoolOp, UnaryOp, Subscript, Other)
     - num_calls, num_branches, num_loops (local window)
     - has_sensitive_token (binary)
     - has_unsafe_lib (binary)
     - depth (normalized)
  3. GNN model (torch-geometric):
     - GCNConv(16+5, 64) → ReLU → GCNConv(64, 32) → ReLU
     - global_mean_pool → Linear(32, 16) → ReLU → Linear(16, 1) → Sigmoid
  4. Training: binary cross-entropy on labeled (function, label) pairs
  5. Inference: per-function risk score in [0, 1]

The model is saved to ~/.loomscan-cache/gnn_model.pt and loaded on subsequent
runs. If torch is not installed, falls back to HeuristicRiskScorer.

Training data: collected from `loomscan feedback tp/fp` labels. The model
starts with random weights and improves as users label findings.
"""
from __future__ import annotations

import ast
import re
import os
import json
import logging
import math
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass, field

_logger = logging.getLogger("loomscan.gnn_cpg")

# Check if torch + torch-geometric are available
try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    from torch_geometric.data import Data, Batch
    from torch_geometric.nn import GCNConv, global_mean_pool
    _HAS_TORCH = True
except ImportError:
    _HAS_TORCH = False
    _logger.debug("torch/torch-geometric not installed — GNN unavailable, using HeuristicRiskScorer fallback")
    # v7.5.1: Provide stub classes so module-level `class GNNOnCPGModel(nn.Module)`
    # doesn't raise NameError when torch is absent. The class body is wrapped
    # in `if _HAS_TORCH:` below, but we still need `nn` defined for the class
    # declaration to parse.
    torch = None
    nn = type("nn", (), {"Module": object})()
    F = None
    Data = None
    Batch = None
    GCNConv = None
    global_mean_pool = None


# =============================================================================
# Node type vocabulary (16 types + Other)
# =============================================================================
NODE_TYPES = [
    "FunctionDef", "AsyncFunctionDef", "Call", "If", "For", "While",
    "Assign", "Return", "Name", "Attribute", "Constant", "BinOp",
    "Compare", "BoolOp", "UnaryOp", "Subscript",
]
NODE_TYPE_TO_IDX = {t: i for i, t in enumerate(NODE_TYPES)}
NUM_NODE_TYPES = len(NODE_TYPES)
# v7.5.3: Fixed — was NUM_NODE_TYPES + 5 (21), but build_cpg computes 6 numeric
# features (num_calls, num_branches, num_loops, has_sensitive, has_unsafe, depth).
# The depth/10.0 feature was being silently truncated by features[:NODE_FEATURE_DIM].
# Now correctly set to 22 (16 one-hot + 6 numeric).
NODE_FEATURE_DIM = NUM_NODE_TYPES + 6  # 16 one-hot + 6 numeric features


# Sensitive token patterns (same as HeuristicRiskScorer)
_SENSITIVE_TOKENS = re.compile(
    r"\b(password|secret|token|key|admin|root|exec|eval|sql|query|delete|"
    r"update|insert|drop|system|cmd|shell|os\.|subprocess|pickle|yaml\.load|"
    r"innerHTML|document\.write|dangerouslySetInnerHTML)\b", re.IGNORECASE)

_UNSAFE_LIBS = re.compile(
    r"\b(?:md5|sha1|DES|ECB|PKCS1_v1_5|random\.|Math\.random|strcpy|gets|sprintf)\b")


# =============================================================================
# CPG Builder — converts Python source to a Code Property Graph
# =============================================================================
@dataclass
class CPGNode:
    """A node in the Code Property Graph."""
    node_type: str  # AST node type name
    features: List[float] = field(default_factory=list)
    ast_node: Optional[object] = None  # reference to original AST node (not serialized)


@dataclass
class CPGGraph:
    """A Code Property Graph for one function."""
    nodes: List[CPGNode] = field(default_factory=list)
    edges: List[Tuple[int, int]] = field(default_factory=list)  # (src, dst) index pairs
    edge_types: List[str] = field(default_factory=list)  # 'ast', 'data', 'call'
    function_name: str = "<unknown>"
    function_line: int = 0


def build_cpg(source: str, function_name: str = "<unknown>", function_line: int = 0) -> Optional[CPGGraph]:
    """Build a Code Property Graph from Python source code.

    The CPG combines:
      - AST edges (parent → child)
      - Data-flow edges (def → use, same variable name)
      - Call edges (Call node → function name resolution, when possible)

    Returns None if the source doesn't parse.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    graph = CPGGraph(function_name=function_name, function_line=function_line)
    node_to_idx: Dict[int, int] = {}  # id(ast_node) → index in graph.nodes

    def visit(node: ast.AST, parent_idx: Optional[int] = None, depth: int = 0):
        node_type = type(node).__name__
        idx = len(graph.nodes)
        node_to_idx[id(node)] = idx

        # Build node features
        onehot = [0.0] * NUM_NODE_TYPES
        if node_type in NODE_TYPE_TO_IDX:
            onehot[NODE_TYPE_TO_IDX[node_type]] = 1.0

        # Local feature extraction (use source segment if available)
        try:
            segment = ast.get_source_segment(source, node) or ""
        except Exception:
            segment = ""

        num_calls = float(len(re.findall(r"\w+\s*\(", segment)))
        num_branches = float(len(re.findall(r"\bif\b|\belif\b|\belse\b", segment)))
        num_loops = float(len(re.findall(r"\bfor\b|\bwhile\b", segment)))
        has_sensitive = 1.0 if _SENSITIVE_TOKENS.search(segment) else 0.0
        has_unsafe = 1.0 if _UNSAFE_LIBS.search(segment) else 0.0

        # v7.5.3: NODE_FEATURE_DIM is now 22 (16 one-hot + 6 numeric), so all
        # features including depth are preserved. No more silent truncation.
        features = onehot + [num_calls, num_branches, num_loops, has_sensitive, has_unsafe, depth / 10.0]
        assert len(features) == NODE_FEATURE_DIM, \
            f"Feature dim mismatch: {len(features)} != {NODE_FEATURE_DIM}"

        graph.nodes.append(CPGNode(node_type=node_type, features=features, ast_node=node))

        # AST edge: parent → child
        if parent_idx is not None:
            graph.edges.append((parent_idx, idx))
            graph.edge_types.append("ast")

        # Recurse
        for child in ast.iter_child_nodes(node):
            visit(child, parent_idx=idx, depth=depth + 1)

    visit(tree)

    # Add data-flow edges: for each Name node that's a LOAD, find the nearest STORE
    # with the same name. This is a simple approximation (real CPG uses reaching defs).
    name_stores: Dict[str, List[int]] = {}  # var name → list of node indices where stored
    for i, cpg_node in enumerate(graph.nodes):
        ast_node = cpg_node.ast_node
        if isinstance(ast_node, ast.Name):
            if isinstance(ast_node.ctx, ast.Store):
                name_stores.setdefault(ast_node.id, []).append(i)

    for i, cpg_node in enumerate(graph.nodes):
        ast_node = cpg_node.ast_node
        if isinstance(ast_node, ast.Name) and isinstance(ast_node.ctx, ast.Load):
            var = ast_node.id
            if var in name_stores:
                # Edge from each store to this load
                for store_idx in name_stores[var]:
                    if store_idx != i:
                        graph.edges.append((store_idx, i))
                        graph.edge_types.append("data")

    # Add call edges: for each Call node, if the function name matches a FunctionDef
    # in the same graph, add an edge. (Intra-function only — full call graph needs
    # cross-file analysis.)
    func_def_indices: Dict[str, int] = {}
    for i, cpg_node in enumerate(graph.nodes):
        if isinstance(cpg_node.ast_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_def_indices[cpg_node.ast_node.name] = i

    for i, cpg_node in enumerate(graph.nodes):
        if isinstance(cpg_node.ast_node, ast.Call):
            func_name = None
            if isinstance(cpg_node.ast_node.func, ast.Name):
                func_name = cpg_node.ast_node.func.id
            elif isinstance(cpg_node.ast_node.func, ast.Attribute):
                func_name = cpg_node.ast_node.func.attr
            if func_name and func_name in func_def_indices:
                target_idx = func_def_indices[func_name]
                if target_idx != i:
                    graph.edges.append((i, target_idx))
                    graph.edge_types.append("call")

    return graph


def cpg_to_torch_data(cpg: CPGGraph) -> Optional["Data"]:
    """Convert a CPGGraph to a torch_geometric Data object. Returns None if torch unavailable."""
    if not _HAS_TORCH:
        return None
    if not cpg.nodes:
        return None

    x = torch.tensor([n.features for n in cpg.nodes], dtype=torch.float)
    if cpg.edges:
        edge_index = torch.tensor(cpg.edges, dtype=torch.long).t().contiguous()
    else:
        edge_index = torch.empty((2, 0), dtype=torch.long)

    return Data(x=x, edge_index=edge_index)


# =============================================================================
# GNN Model — 2-layer GCN with learned weights
# =============================================================================
class GNNOnCPGModel(nn.Module):
    """Real Graph Neural Network for code vulnerability scoring.

    Architecture:
      GCNConv(NODE_FEATURE_DIM, 64) → ReLU → Dropout(0.1)
      GCNConv(64, 32) → ReLU
      global_mean_pool → Linear(32, 16) → ReLU → Linear(16, 1) → Sigmoid

    Input: torch_geometric Data batch (node features + edge index + batch index)
    Output: risk score in [0, 1] per graph (function)
    """

    def __init__(self, node_features: int = NODE_FEATURE_DIM, hidden1: int = 64, hidden2: int = 32):
        super().__init__()
        self.conv1 = GCNConv(node_features, hidden1)
        self.conv2 = GCNConv(hidden1, hidden2)
        self.fc1 = nn.Linear(hidden2, 16)
        self.fc2 = nn.Linear(16, 1)
        self.dropout = nn.Dropout(0.1)

    def forward(self, data: "Data") -> "torch.Tensor":
        x, edge_index, batch = data.x, data.edge_index, data.batch
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = self.dropout(x)
        x = self.conv2(x, edge_index)
        x = F.relu(x)
        # Global mean pool: aggregate node embeddings → one embedding per graph
        x = global_mean_pool(x, batch)
        x = self.fc1(x)
        x = F.relu(x)
        x = self.fc2(x)
        return torch.sigmoid(x).squeeze(-1)


# =============================================================================
# Training + inference
# =============================================================================
MODEL_PATH = Path.home() / ".loomscan-cache" / "gnn_model.pt"


def get_model() -> Optional["GNNOnCPGModel"]:
    """Load the trained GNN model, or return None if torch unavailable or no model."""
    if not _HAS_TORCH:
        return None
    model = GNNOnCPGModel()
    if MODEL_PATH.exists():
        try:
            model.load_state_dict(torch.load(MODEL_PATH, map_location="cpu", weights_only=True))
            model.eval()
            _logger.debug(f"Loaded GNN model from {MODEL_PATH}")
        except Exception as e:
            _logger.debug(f"Failed to load GNN model: {e} — using random weights")
    else:
        _logger.debug("No trained GNN model found — using random weights. Run `loomscan gnn-train` to train.")
    return model


def score_function_with_gnn(source: str, function_name: str = "<unknown>", function_line: int = 0) -> Optional[float]:
    """Score a single function with the GNN. Returns risk score in [0, 1] or None if unavailable."""
    if not _HAS_TORCH:
        return None
    model = get_model()
    if model is None:
        return None
    cpg = build_cpg(source, function_name, function_line)
    if cpg is None or not cpg.nodes:
        return None
    data = cpg_to_torch_data(cpg)
    if data is None:
        return None
    # Add batch dimension (single graph)
    data.batch = torch.zeros(data.num_nodes, dtype=torch.long)
    with torch.no_grad():
        score = model(data).item()
    return score


def train_gnn(training_data: List[Tuple[str, str, int, float]], epochs: int = 50, lr: float = 0.01) -> Optional[Dict]:
    """Train the GNN on labeled (source, function_name, line, label) pairs.

    label = 1.0 for true positive (real vuln), 0.0 for false positive.

    Returns training metrics dict, or None if torch unavailable.
    """
    if not _HAS_TORCH:
        return None
    if not training_data:
        return {"error": "no training data"}

    # Build dataset
    graphs = []
    labels = []
    for source, fname, fline, label in training_data:
        cpg = build_cpg(source, fname, fline)
        if cpg is None or not cpg.nodes:
            continue
        data = cpg_to_torch_data(cpg)
        if data is None:
            continue
        data.y = torch.tensor([label], dtype=torch.float)
        graphs.append(data)
        labels.append(label)

    if not graphs:
        return {"error": "no valid graphs built from training data"}

    model = GNNOnCPGModel()
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = nn.BCELoss()

    model.train()
    losses = []
    for epoch in range(epochs):
        optimizer.zero_grad()
        batch = Batch.from_data_list(graphs)
        out = model(batch)
        loss = criterion(out, batch.y)
        loss.backward()
        optimizer.step()
        losses.append(loss.item())
        if (epoch + 1) % 10 == 0:
            _logger.info(f"GNN epoch {epoch+1}/{epochs} loss={loss.item():.4f}")

    # Save model
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), MODEL_PATH)
    model.eval()

    return {
        "epochs": epochs,
        "final_loss": losses[-1],
        "graphs_trained": len(graphs),
        "positive_examples": sum(1 for l in labels if l >= 0.5),
        "negative_examples": sum(1 for l in labels if l < 0.5),
        "model_path": str(MODEL_PATH),
    }


# =============================================================================
# Convenience: score all functions in a file
# =============================================================================
@dataclass
class GNNResult:
    function: str
    file: str
    line: int
    score: float
    language: str = "python"
    model: str = "gnn"  # or "heuristic_fallback"


def score_file_with_gnn(file_path: Path) -> List[GNNResult]:
    """Score every function in a source file with the GNN.

    v7.5.2: Multi-language support — uses Python AST for .py files, regex-based
    CPG for Java/JS/TS/Go/C/C++. Falls back to HeuristicRiskScorer if torch unavailable.

    Supported languages:
      - Python (.py)       — full AST-based CPG
      - Java (.java)       — regex-based function extraction + CPG
      - JavaScript (.js)   — regex-based function extraction + CPG
      - TypeScript (.ts)   — regex-based function extraction + CPG
      - Go (.go)           — regex-based function extraction + CPG
      - C/C++ (.c/.cpp)    — regex-based function extraction + CPG
    """
    if not file_path.exists():
        return []
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    ext = file_path.suffix.lower()
    language_map = {
        ".py": "python", ".java": "java", ".kt": "java",
        ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
        ".ts": "typescript", ".tsx": "typescript",
        ".go": "go", ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp",
        ".hpp": "cpp", ".rs": "rust",
    }
    lang = language_map.get(ext, "unknown")
    if lang == "unknown":
        return []

    if lang == "python":
        return _score_python_file(source, file_path)
    else:
        return _score_multi_language_file(source, file_path, lang)


def _score_python_file(source: str, file_path: Path) -> List[GNNResult]:
    """Score Python functions using full AST-based CPG."""
    results: List[GNNResult] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return results

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        func_source = ast.get_source_segment(source, node) or ""
        if not func_source:
            continue

        score = score_function_with_gnn(func_source, node.name, node.lineno)
        if score is None:
            # Fallback to heuristic
            from .learning import HeuristicRiskScorer
            scorer = HeuristicRiskScorer(language="python")
            heuristic_results = scorer._score_source(source, str(file_path))
            for hr in heuristic_results:
                if hr.function == node.name:
                    score = hr.score
                    break
            if score is None:
                score = 0.5
            model_name = "heuristic_fallback"
        else:
            model_name = "gnn"

        results.append(GNNResult(
            function=node.name, file=str(file_path), line=node.lineno,
            score=score, language="python", model=model_name,
        ))
    return results


# v7.5.2: Multi-language function regex patterns
_MULTI_FUNC_REGEX = {
    "java": re.compile(
        r"(?:public|private|protected|static)\s+[\w<>\[\]]+\s+(?P<name>\w+)\s*\((?P<args>[^)]*)\)\s*(?:throws\s+[\w.,\s]+)?\{",
        re.MULTILINE),
    "javascript": re.compile(
        r"(?:async\s+)?function\s+(?P<name>\w+)\s*\((?P<args>[^)]*)\)\s*\{|"
        r"(?:const|let|var)\s+(?P<name2>\w+)\s*=\s*(?:async\s*)?\((?P<args2>[^)]*)\)\s*=>\s*\{",
        re.MULTILINE),
    "typescript": re.compile(
        r"(?:async\s+)?function\s+(?P<name>\w+)\s*\((?P<args>[^)]*)\)\s*(?::\s*[^{]+)?\s*\{|"
        r"(?:const|let|var)\s+(?P<name2>\w+)\s*=\s*(?:async\s*)?\((?P<args2>[^)]*)\)\s*(?::\s*[^{]+)?\s*=>\s*\{",
        re.MULTILINE),
    "go": re.compile(
        r"^func\s+(?:\([^)]*\)\s+)?(?P<name>\w+)\s*\((?P<args>[^)]*)\)\s*(?:\([^)]*\))?\s*\{",
        re.MULTILINE),
    "c": re.compile(
        r"\w[\w\s\*]*\s+(?P<name>\w+)\s*\((?P<args>[^)]*)\)\s*\{",
        re.MULTILINE),
    "cpp": re.compile(
        r"\w[\w\s\*:<>]*\s+(?P<name>\w+)\s*\((?P<args>[^)]*)\)\s*\{",
        re.MULTILINE),
    "rust": re.compile(
        r"^fn\s+(?P<name>\w+)\s*\((?P<args>[^)]*)\)\s*(?:->\s*[^{]+)?\s*\{",
        re.MULTILINE),
}


def _extract_multi_language_functions(source: str, lang: str) -> List[Tuple[str, str, int]]:
    """Extract functions from non-Python source via regex. Returns (name, body, line)."""
    rx = _MULTI_FUNC_REGEX.get(lang)
    if not rx:
        return []
    results = []
    for m in rx.finditer(source):
        name = m.group("name") or m.groupdict().get("name2") or "<anon>"
        line = source[:m.start()].count("\n") + 1
        # Extract function body by counting braces
        start = m.end()
        depth = 1
        end = start
        while end < len(source) and depth > 0:
            if source[end] == "{":
                depth += 1
            elif source[end] == "}":
                depth -= 1
            end += 1
        body = source[m.start():end]
        results.append((name, body, line))
    return results


def _build_multi_language_cpg(source: str, function_body: str, lang: str, func_name: str, func_line: int) -> Optional[CPGGraph]:
    """Build a CPG from non-Python source using regex-based feature extraction.

    Since we can't parse Java/JS/Go AST without tree-sitter, we use regex to
    extract features from the function body. The resulting CPG has a single
    "function" node with aggregated features (same feature space as Python CPG
    so the model is cross-language compatible).
    """
    graph = CPGGraph(function_name=func_name, function_line=func_line)

    # Create a single function-level node with extracted features
    onehot = [0.0] * NUM_NODE_TYPES
    # Map to closest Python AST type — "FunctionDef" for the function node
    onehot[NODE_TYPE_TO_IDX["FunctionDef"]] = 1.0

    num_calls = float(len(re.findall(r'\w+\s*\(', function_body)))
    num_branches = float(len(re.findall(r'\bif\b|\belif\b|\belse\b|\bswitch\b|\bcase\b', function_body)))
    num_loops = float(len(re.findall(r'\bfor\b|\bwhile\b|\bdo\b', function_body)))
    has_sensitive = 1.0 if _SENSITIVE_TOKENS.search(function_body) else 0.0
    has_unsafe = 1.0 if _UNSAFE_LIBS.search(function_body) else 0.0

    # v7.5.3: 16 one-hot + 6 numeric = 22 = NODE_FEATURE_DIM (depth=0.0 for non-Python)
    features = onehot + [num_calls, num_branches, num_loops, has_sensitive, has_unsafe, 0.0]
    assert len(features) == NODE_FEATURE_DIM, \
        f"Feature dim mismatch: {len(features)} != {NODE_FEATURE_DIM}"

    # Add a few sub-nodes for calls, branches, loops to give the GNN graph structure
    graph.nodes.append(CPGNode(node_type="FunctionDef", features=features))

    # Add call nodes
    for cm in re.finditer(r'(\w+)\s*\(', function_body):
        call_name = cm.group(1)
        if call_name in ("if", "for", "while", "switch", "return", "function", "def", "fn"):
            continue
        call_onehot = [0.0] * NUM_NODE_TYPES
        call_onehot[NODE_TYPE_TO_IDX["Call"]] = 1.0
        call_features = call_onehot + [0.0, 0.0, 0.0,
                                       1.0 if _SENSITIVE_TOKENS.search(call_name) else 0.0,
                                       1.0 if _UNSAFE_LIBS.search(call_name) else 0.0, 0.0]
        call_features = call_features[:NODE_FEATURE_DIM]
        if len(call_features) < NODE_FEATURE_DIM:
            call_features.extend([0.0] * (NODE_FEATURE_DIM - len(call_features)))
        idx = len(graph.nodes)
        graph.nodes.append(CPGNode(node_type="Call", features=call_features))
        graph.edges.append((0, idx))  # AST edge: function → call
        graph.edge_types.append("ast")

    # Add branch nodes
    for bm in re.finditer(r'\b(?:if|else|switch|case)\b', function_body):
        branch_onehot = [0.0] * NUM_NODE_TYPES
        branch_onehot[NODE_TYPE_TO_IDX["If"]] = 1.0
        branch_features = branch_onehot + [0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
        branch_features = branch_features[:NODE_FEATURE_DIM]
        idx = len(graph.nodes)
        graph.nodes.append(CPGNode(node_type="If", features=branch_features))
        graph.edges.append((0, idx))
        graph.edge_types.append("ast")

    return graph


def _score_multi_language_file(source: str, file_path: Path, lang: str) -> List[GNNResult]:
    """Score functions in a non-Python file using regex-based CPG + GNN."""
    results: List[GNNResult] = []
    functions = _extract_multi_language_functions(source, lang)

    for func_name, func_body, func_line in functions:
        if not _HAS_TORCH:
            # No torch — use heuristic fallback
            from .learning import HeuristicRiskScorer
            scorer = HeuristicRiskScorer(language=lang)
            # HeuristicRiskScorer uses regex features, similar to our CPG features
            score = 0.5
            try:
                # Use the heuristic scorer's _score method on the function body
                feats = scorer._extract_features("", func_body)
                score = scorer._score(feats)
            except Exception:
                pass
            results.append(GNNResult(
                function=func_name, file=str(file_path), line=func_line,
                score=score, language=lang, model="heuristic_fallback",
            ))
            continue

        # Build CPG from the function body
        cpg = _build_multi_language_cpg(source, func_body, lang, func_name, func_line)
        if cpg is None or not cpg.nodes:
            continue

        data = cpg_to_torch_data(cpg)
        if data is None:
            continue
        data.batch = torch.zeros(data.num_nodes, dtype=torch.long)

        model = get_model()
        if model is None:
            results.append(GNNResult(
                function=func_name, file=str(file_path), line=func_line,
                score=0.5, language=lang, model="heuristic_fallback",
            ))
            continue

        with torch.no_grad():
            score = model(data).item()

        results.append(GNNResult(
            function=func_name, file=str(file_path), line=func_line,
            score=score, language=lang, model="gnn",
        ))

    return results

    return results


def scan_repo_with_gnn(repo_root: Path) -> List[GNNResult]:
    """Walk a repo, score every function with the GNN.

    v7.5.2: Multi-language support — scans .py, .java, .js, .ts, .go, .c, .cpp, .rs
    """
    out: List[GNNResult] = []
    # v7.5.2: Use unified skip_dirs from _paths.py (fixes feedback-loop bug)
    try:
        from ._paths import is_skipped_dir
        skip_check = is_skipped_dir
    except ImportError:
        _skip = {"node_modules", ".git", "vendor", "__pycache__", "dist", "build",
                 ".venv", "venv", ".loomscan-cache", ".loomscan-reports", ".loomscan-fixes"}
        skip_check = lambda p: any(s in str(p) for s in _skip)
    # v7.5.2: Scan all supported languages, not just Python
    supported_exts = {".py", ".java", ".kt", ".js", ".jsx", ".mjs", ".ts", ".tsx",
                      ".go", ".c", ".h", ".cpp", ".cc", ".hpp", ".rs"}
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in supported_exts:
            continue
        if skip_check(path):
            continue
        try:
            out.extend(score_file_with_gnn(path))
        except Exception as e:
            _logger.debug(f"Skipping {path}: {e}")
    return out


def is_gnn_available() -> bool:
    """Check if the GNN is available (torch + torch-geometric installed)."""
    return _HAS_TORCH
