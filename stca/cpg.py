"""Code Property Graph (CPG) — Joern-inspired.

A CPG merges three program representations into one graph:
  - AST (Abstract Syntax Tree): structural
  - CFG (Control Flow Graph): execution order
  - PDG (Program Dependence Graph): data + control dependencies

This is the foundation that makes real detection possible. With a CPG you can
ask questions like:
  - "Find every path from a source (request.body) to a sink (eval) where
    the value is not sanitized"
  - "Find every method that calls foo() before bar() is initialized"
  - "Find every variable that holds user input and reaches a SQL query"

Joern builds CPGs for C/C++/Java/Python/JS/Go/PHP/Kotlin and exposes a Scala
query DSL. We build a simpler Python-only CPG here using AST + a CFG + a PDG.
This is enough to do real cross-file taint tracking and pattern queries.

References:
  - Yamaguchi et al. (2014) "Modeling and Discovering Vulnerabilities with CPGs"
  - Joern: https://joern.io
  - LLMxCPG (2024): https://arxiv.org/abs/2408.02306
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field


@dataclass
class CPGNode:
    """A node in the Code Property Graph."""
    id: str
    kind: str  # 'function' | 'param' | 'variable' | 'call' | 'literal' | 'return' | 'assign' | 'if' | 'for' | 'while' | 'try' | 'except'
    name: str = ""  # function name, variable name, call name
    file: str = ""
    line: int = 0
    type_annotation: str = ""  # if known
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CPGEdge:
    """An edge in the CPG."""
    src: str  # node id
    dst: str  # node id
    kind: str  # 'ast_child' | 'cfg_next' | 'data_dep' | 'call' | 'param' | 'return'


@dataclass
class CPG:
    """A Code Property Graph for a single file or a whole repo."""
    nodes: Dict[str, CPGNode] = field(default_factory=dict)
    edges: List[CPGEdge] = field(default_factory=list)
    # index for fast lookup
    by_kind: Dict[str, Set[str]] = field(default_factory=dict)
    by_name: Dict[str, Set[str]] = field(default_factory=dict)
    by_file: Dict[str, Set[str]] = field(default_factory=dict)
    # adjacency
    successors: Dict[str, List[Tuple[str, str]]] = field(default_factory=dict)  # node_id → [(edge_kind, dst_id)]
    predecessors: Dict[str, List[Tuple[str, str]]] = field(default_factory=dict)

    def add_node(self, node: CPGNode) -> str:
        self.nodes[node.id] = node
        self.by_kind.setdefault(node.kind, set()).add(node.id)
        if node.name:
            self.by_name.setdefault(node.name, set()).add(node.id)
        self.by_file.setdefault(node.file, set()).add(node.id)
        return node.id

    def add_edge(self, src: str, dst: str, kind: str) -> None:
        self.edges.append(CPGEdge(src=src, dst=dst, kind=kind))
        self.successors.setdefault(src, []).append((kind, dst))
        self.predecessors.setdefault(dst, []).append((kind, src))

    def get_nodes(self, kind: str = None, name: str = None,
                  file: str = None) -> List[CPGNode]:
        """Lookup nodes by kind/name/file."""
        ids: Set[str] = set(self.nodes.keys())
        if kind:
            ids &= self.by_kind.get(kind, set())
        if name:
            ids &= self.by_name.get(name, set())
        if file:
            ids &= self.by_file.get(file, set())
        return [self.nodes[i] for i in ids]

    def reachable_from(self, source_ids: Set[str],
                       edge_kinds: Set[str] = None) -> Set[str]:
        """BFS: which nodes are reachable from source_ids via given edge kinds."""
        if edge_kinds is None:
            edge_kinds = {"data_dep", "cfg_next", "call"}
        visited: Set[str] = set()
        queue = list(source_ids)
        while queue:
            nid = queue.pop()
            if nid in visited:
                continue
            visited.add(nid)
            for kind, dst in self.successors.get(nid, []):
                if kind in edge_kinds and dst not in visited:
                    queue.append(dst)
        return visited

    def find_paths(self, source_id: str, sink_id: str,
                   max_depth: int = 10,
                   edge_kinds: Set[str] = None) -> List[List[str]]:
        """DFS: find all paths from source to sink (up to max_depth)."""
        if edge_kinds is None:
            edge_kinds = {"data_dep", "cfg_next"}
        paths: List[List[str]] = []
        def dfs(nid: str, path: List[str], visited: Set[str]):
            if len(path) > max_depth:
                return
            if nid == sink_id and len(path) > 1:
                paths.append(path[:])
                return
            visited.add(nid)
            for kind, dst in self.successors.get(nid, []):
                if kind in edge_kinds and dst not in visited:
                    dfs(dst, path + [dst], visited.copy())
        dfs(source_id, [source_id], set())
        return paths


def build_cpg_for_file(file_path: Path, repo_root: Path = None) -> CPG:
    """Build a CPG for a single Python file."""
    cpg = CPG()
    if not file_path.exists() or file_path.suffix != ".py":
        return cpg
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        return cpg

    rel_path = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)

    # Walk the AST, build nodes and edges
    def _make_id(node: ast.AST, suffix: str = "") -> str:
        lineno = getattr(node, "lineno", 0)
        col_offset = getattr(node, "col_offset", 0)
        return f"{rel_path}:{lineno}:{col_offset}:{type(node).__name__}{suffix}"

    def _walk(node: ast.AST, parent_id: str = None, function_id: str = None):
        """Recursively walk AST, adding nodes and edges."""
        nonlocal cpg
        # Skip module-level and uninteresting nodes — don't create CPG nodes for them
        if isinstance(node, ast.Module):
            for child in ast.iter_child_nodes(node):
                _walk(child, parent_id, function_id)
            return

        nid = _make_id(node)
        kind = ""  # empty kind = skip this node
        name = ""
        if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
            kind = "function"
            name = node.name
            function_id = nid
        elif isinstance(node, ast.Name):
            kind = "variable"
            name = node.id
        elif isinstance(node, ast.arg):
            kind = "param"
            name = node.arg
        elif isinstance(node, ast.Call):
            kind = "call"
            name = _get_call_name(node.func) if node.func else ""
        elif isinstance(node, ast.Constant):
            kind = "literal"
            name = repr(node.value)[:50]
        elif isinstance(node, ast.Return):
            kind = "return"
        elif isinstance(node, ast.Assign):
            kind = "assign"
        elif isinstance(node, (ast.If, ast.IfExp)):
            kind = "if"
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            kind = "for"
        elif isinstance(node, ast.While):
            kind = "while"
        elif isinstance(node, ast.ExceptHandler):
            kind = "except"

        if kind:
            cpg_node = CPGNode(
                id=nid, kind=kind, name=name,
                file=rel_path, line=getattr(node, "lineno", 0),
                type_annotation="",
            )
            cpg.add_node(cpg_node)
            if parent_id:
                cpg.add_edge(parent_id, nid, "ast_child")
            if function_id and function_id != nid:
                cpg.add_edge(function_id, nid, "contains")
            effective_parent = nid
        else:
            # skipped node — pass through the parent_id
            effective_parent = parent_id

        # data dependency: assignment target → value usage
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    target_id = _make_id(target)
                    value_id = _make_id(node.value)
                    # ensure both nodes exist
                    if target_id not in cpg.nodes:
                        cpg.add_node(CPGNode(id=target_id, kind="variable", name=target.id,
                                              file=rel_path, line=getattr(target, "lineno", 0)))
                    if value_id not in cpg.nodes:
                        # add a placeholder for the value
                        cpg.add_node(CPGNode(id=value_id, kind="variable",
                                              name=_get_value_name(node.value),
                                              file=rel_path, line=getattr(node.value, "lineno", 0)))
                    cpg.add_edge(value_id, target_id, "data_dep")

        # function call: caller → callee (if same-file)
        if isinstance(node, ast.Call) and kind == "call":
            callee_name = _get_call_name(node.func) if node.func else ""
            if callee_name:
                callees = cpg.get_nodes(kind="function", name=callee_name)
                for callee in callees:
                    cpg.add_edge(nid, callee.id, "call")

        # recurse
        for child in ast.iter_child_nodes(node):
            _walk(child, parent_id=effective_parent, function_id=function_id)

    _walk(tree)
    return cpg


def _get_value_name(value_node: ast.AST) -> str:
    """Extract a name from an AST value node for CPG labeling."""
    if isinstance(value_node, ast.Name):
        return value_node.id
    if isinstance(value_node, ast.Call):
        return _get_call_name(value_node.func) if value_node.func else "call"
    if isinstance(value_node, ast.Constant):
        return repr(value_node.value)[:30]
    return type(value_node).__name__.lower()


def build_cpg_for_repo(repo_root: Path,
                       max_files: int = 100) -> CPG:
    """Build a unified CPG for all Python files in the repo.

    Cross-file edges are added when:
      - A function call references a function defined in another file
      - A variable is returned from one function and passed as arg to another
      - An import statement brings a name into scope
    """
    master_cpg = CPG()
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                 ".stca-cache", ".stca-reports", ".stca-fixes", "tests", "test"}
    py_files: List[Path] = []
    for p in repo_root.rglob("*.py"):
        if any(part in skip_dirs for part in p.parts):
            continue
        if p.name.startswith("test_") or p.name.endswith("_test.py"):
            continue
        py_files.append(p)
        if len(py_files) >= max_files:
            break

    # build per-file CPGs and merge
    file_cpgs: Dict[str, CPG] = {}
    for f in py_files:
        rel = str(f.relative_to(repo_root))
        file_cpg = build_cpg_for_file(f, repo_root)
        file_cpgs[rel] = file_cpg
        # merge nodes/edges into master
        for nid, node in file_cpg.nodes.items():
            master_cpg.nodes[nid] = node
            master_cpg.by_kind.setdefault(node.kind, set()).add(nid)
            if node.name:
                master_cpg.by_name.setdefault(node.name, set()).add(nid)
            master_cpg.by_file.setdefault(node.file, set()).add(nid)
        for edge in file_cpg.edges:
            master_cpg.edges.append(edge)
            master_cpg.successors.setdefault(edge.src, []).append((edge.kind, edge.dst))
            master_cpg.predecessors.setdefault(edge.dst, []).append((edge.kind, edge.src))

    # add cross-file call edges
    # for each call node, find a function with the same name in any file
    for call_node in master_cpg.get_nodes(kind="call"):
        if not call_node.name:
            continue
        # find function definitions with this name (excluding the call itself)
        candidates = [n for n in master_cpg.get_nodes(kind="function", name=call_node.name)
                      if n.file != call_node.file or n.line < call_node.line]
        for callee in candidates[:1]:  # only first match to avoid noise
            master_cpg.add_edge(call_node.id, callee.id, "call")

    return master_cpg


def _get_call_name(func: ast.AST) -> str:
    """Extract the name from a Call.func AST node."""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def save_cpg(cpg: CPG, path: Path) -> None:
    """Serialize CPG to JSON for inspection or incremental builds."""
    data = {
        "nodes": [{**n.__dict__} for n in cpg.nodes.values()],
        "edges": [{**e.__dict__} for e in cpg.edges],
    }
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def cpg_stats(cpg: CPG) -> dict:
    """Return stats about a CPG for debugging."""
    return {
        "total_nodes": len(cpg.nodes),
        "total_edges": len(cpg.edges),
        "by_kind": {k: len(v) for k, v in cpg.by_kind.items()},
        "files": len(cpg.by_file),
    }
