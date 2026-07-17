"""Tests for loomscan.gnn_cpg — the REAL Graph Neural Network on Code Property Graph.

v7.5: This is a real GNN (torch-geometric GCNConv with learned weights), NOT
the HeuristicRiskScorer (hand-tuned logistic regression) from v7.3.4.
"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from loomscan.gnn_cpg import (
    build_cpg,
    cpg_to_torch_data,
    GNNOnCPGModel,
    score_function_with_gnn,
    score_file_with_gnn,
    train_gnn,
    scan_repo_with_gnn,
    is_gnn_available,
    GNNResult,
    NODE_TYPES,
    NODE_FEATURE_DIM,
)

# Skip all tests if torch unavailable
pytestmark = pytest.mark.skipif(not is_gnn_available(), reason="torch + torch-geometric not installed")


# Test fixtures
SAFE_CODE = '''
def add(a, b):
    """Add two numbers. Safe — no security risk."""
    return a + b
'''

SQL_INJECTION_CODE = '''
def login(username, password):
    """SQL injection — string concat in query."""
    query = "SELECT * FROM users WHERE name='" + username + "'"
    cursor = db.execute(query)
    return cursor.fetchone()
'''

EVAL_INJECTION_CODE = '''
def run_user_code(code_str):
    """Code injection — eval on user input."""
    result = eval(code_str)
    return result
'''


class TestCPGBuilder:
    """Test the Code Property Graph builder."""

    def test_build_cpg_returns_graph(self):
        """build_cpg should return a CPGGraph with nodes and edges."""
        cpg = build_cpg(SAFE_CODE, "add", 1)
        assert cpg is not None
        assert len(cpg.nodes) > 0, "CPG should have at least one node"
        assert len(cpg.edges) > 0, "CPG should have at least one AST edge"
        assert cpg.function_name == "add"

    def test_build_cpg_invalid_syntax_returns_none(self):
        """build_cpg should return None for invalid Python."""
        cpg = build_cpg("def broken(:", "broken", 1)
        assert cpg is None

    def test_cpg_has_ast_edges(self):
        """CPG should have AST edges (parent → child)."""
        cpg = build_cpg(SAFE_CODE, "add", 1)
        assert "ast" in cpg.edge_types, "CPG should have AST edges"

    def test_cpg_has_data_flow_edges(self):
        """CPG should have data-flow edges for variable use."""
        cpg = build_cpg(SQL_INJECTION_CODE, "login", 1)
        # query variable is stored then loaded in db.execute(query)
        assert "data" in cpg.edge_types, "CPG should have data-flow edges"

    def test_node_features_correct_dimension(self):
        """Each node should have NODE_FEATURE_DIM features."""
        cpg = build_cpg(SAFE_CODE, "add", 1)
        for node in cpg.nodes:
            assert len(node.features) == NODE_FEATURE_DIM, \
                f"Node {node.node_type} has {len(node.features)} features, expected {NODE_FEATURE_DIM}"

    def test_node_type_onehot(self):
        """Function nodes should have the FunctionDef one-hot bit set."""
        cpg = build_cpg(SAFE_CODE, "add", 1)
        func_nodes = [n for n in cpg.nodes if n.node_type == "FunctionDef"]
        assert len(func_nodes) >= 1
        # The FunctionDef one-hot bit should be 1.0
        onehot_end = len(NODE_TYPES)
        func_features = func_nodes[0].features[:onehot_end]
        func_idx = NODE_TYPES.index("FunctionDef")
        assert func_features[func_idx] == 1.0, "FunctionDef one-hot bit should be 1.0"


class TestGNNModel:
    """Test the GNN model itself."""

    def test_model_instantiation(self):
        """GNNOnCPGModel should instantiate."""
        model = GNNOnCPGModel()
        assert model is not None

    def test_model_forward_pass(self):
        """Model should produce a score in [0, 1] for a single graph."""
        import torch
        from torch_geometric.data import Data

        cpg = build_cpg(SAFE_CODE, "add", 1)
        data = cpg_to_torch_data(cpg)
        assert data is not None
        # Add batch dimension (single graph)
        data.batch = torch.zeros(data.num_nodes, dtype=torch.long)

        model = GNNOnCPGModel()
        model.eval()
        with torch.no_grad():
            score = model(data).item()
        assert 0.0 <= score <= 1.0, f"Score out of [0,1]: {score}"

    def test_model_has_learned_weights(self):
        """Model should have trainable parameters (not just hardcoded weights)."""
        model = GNNOnCPGModel()
        params = list(model.parameters())
        assert len(params) > 0, "Model should have trainable parameters"
        # Check that conv1 has weight tensors
        assert hasattr(model.conv1, "lin") or hasattr(model.conv1, "weight"), \
            "GCNConv should have weight tensors"


class TestScoring:
    """Test function scoring with the GNN."""

    def test_score_safe_function(self):
        """Safe function should produce a score in [0, 1]."""
        score = score_function_with_gnn(SAFE_CODE, "add", 1)
        assert score is not None
        assert 0.0 <= score <= 1.0

    def test_score_sql_injection(self):
        """SQL injection function should produce a score (untrained, so just check range)."""
        score = score_function_with_gnn(SQL_INJECTION_CODE, "login", 1)
        assert score is not None
        assert 0.0 <= score <= 1.0

    def test_score_file(self):
        """score_file_with_gnn should return GNNResult list."""
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(SQL_INJECTION_CODE + "\n\n" + SAFE_CODE)
            f.flush()
            results = score_file_with_gnn(Path(f.name))
        assert len(results) >= 2, f"Expected >=2 functions, got {len(results)}"
        for r in results:
            assert isinstance(r, GNNResult)
            assert 0.0 <= r.score <= 1.0
            assert r.function in ("login", "add")

    def test_score_invalid_file_returns_empty(self):
        """Invalid Python file should return empty list."""
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write("def broken(:")
            f.flush()
            results = score_file_with_gnn(Path(f.name))
        assert results == []


class TestTraining:
    """Test GNN training (quick smoke test, not full training)."""

    def test_train_gnn_minimal(self):
        """train_gnn should train on minimal data and return metrics."""
        training_data = [
            (SQL_INJECTION_CODE, "login", 1, 1.0),  # TP
            (EVAL_INJECTION_CODE, "run_user_code", 1, 1.0),  # TP
            (SAFE_CODE, "add", 1, 0.0),  # FP
        ]
        # Use very few epochs for test speed
        result = train_gnn(training_data, epochs=3, lr=0.01)
        assert result is not None
        assert "error" not in result, f"Training failed: {result.get('error')}"
        assert result["graphs_trained"] == 3
        assert result["positive_examples"] == 2
        assert result["negative_examples"] == 1
        assert "final_loss" in result
        assert "model_path" in result

    def test_train_gnn_empty_data(self):
        """train_gnn with empty data should return error dict."""
        result = train_gnn([], epochs=1)
        assert result is not None
        assert "error" in result


class TestScanRepo:
    """Test repo-wide GNN scanning."""

    def test_scan_repo_with_gnn(self):
        """scan_repo_with_gnn should score all Python functions in a repo."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            (repo / "safe.py").write_text(SAFE_CODE)
            (repo / "vuln.py").write_text(SQL_INJECTION_CODE)
            results = scan_repo_with_gnn(repo)
            assert len(results) >= 2
            functions = {r.function for r in results}
            assert "add" in functions
            assert "login" in functions
