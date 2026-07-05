"""CPG query DSL — Joern-style pattern queries on the Code Property Graph.

Once you have a CPG, you can ask complex questions as graph queries:
  - "Find every path from a source (request.body) to a sink (eval) where
    the value is not sanitized"
  - "Find every function that calls foo() before bar()"
  - "Find every variable that is assigned but never used"
  - "Find every function with cyclomatic complexity > 10 that touches auth"

Joern exposes a Scala DSL for this. We expose a simple Python query API
plus a YAML-based pattern format for declarative queries.
"""
from __future__ import annotations

from pathlib import Path
from typing import List, Set, Dict, Any, Optional
from dataclasses import dataclass

from .cpg import CPG, CPGNode, build_cpg_for_repo


@dataclass
class CPGQueryResult:
    """A single match for a CPG query."""
    file: str
    line: int
    description: str
    matched_nodes: List[str]  # node IDs
    raw: Dict[str, Any] = None
    cwe: str = ""


def query_unsanitized_taint_flows(cpg: CPG,
                                   sources: Set[str] = None,
                                   sinks: Set[str] = None,
                                   sanitizers: Set[str] = None) -> List[CPGQueryResult]:
    """Find paths from sources to sinks that don't pass through a sanitizer.

    Args:
        sources: set of source function/param names (default: request, input, etc.)
        sinks: set of sink function names (default: eval, exec, etc.)
        sanitizers: set of sanitizer function names that break the flow
    """
    from .taint_cross_file import SOURCE_PARAM_PATTERNS, SINK_PATTERNS, SANITIZER_PATTERNS
    if sources is None:
        sources = set(SOURCE_PARAM_PATTERNS)
    if sinks is None:
        sinks = set(SINK_PATTERNS.keys())
    if sanitizers is None:
        sanitizers = SANITIZER_PATTERNS

    results: List[CPGQueryResult] = []

    # find source nodes (params + source calls)
    source_nodes: List[CPGNode] = []
    for param in cpg.get_nodes(kind="param"):
        if any(s in param.name.lower() for s in sources):
            source_nodes.append(param)
    for call in cpg.get_nodes(kind="call"):
        if call.name in sources:
            source_nodes.append(call)

    # find sink nodes
    sink_nodes = [n for n in cpg.get_nodes(kind="call") if n.name in sinks]
    sink_ids = {n.id for n in sink_nodes}

    # for each source, BFS to find any sink reachable without passing through a sanitizer
    for source in source_nodes:
        visited: Set[str] = set()
        queue: List[str] = [source.id]
        parent: Dict[str, str] = {}

        while queue:
            nid = queue.pop(0)
            if nid in visited:
                continue
            visited.add(nid)

            # check if this is a sink
            if nid in sink_ids and nid != source.id:
                sink_node = cpg.nodes[nid]
                # check if path passes through a sanitizer
                path = _reconstruct_path(parent, source.id, nid)
                if not _path_has_sanitizer(cpg, path, sanitizers):
                    results.append(CPGQueryResult(
                        file=source.file,
                        line=sink_node.line,
                        description=f"Unsanitized flow: {source.name} → {sink_node.name}()",
                        matched_nodes=path,
                        raw={"source": source.name, "sink": sink_node.name,
                             "source_line": source.line, "sink_line": sink_node.line},
                    ))
                continue

            # expand
            for edge_kind, dst in cpg.successors.get(nid, []):
                if edge_kind in ("data_dep", "call") and dst not in visited:
                    parent[dst] = nid
                    queue.append(dst)

    return results


def query_unused_variables(cpg: CPG) -> List[CPGQueryResult]:
    """Find variables that are assigned but never read."""
    results: List[CPGQueryResult] = []
    # find all assign targets
    for node in cpg.get_nodes(kind="assign"):
        # the assign node's children include the target (variable) and value
        for kind, child_id in cpg.successors.get(node.id, []):
            if kind == "ast_child":
                child = cpg.nodes.get(child_id)
                if child and child.kind == "variable":
                    # check if this variable is ever read (appears as a Name in a non-assign context)
                    usages = [n for n in cpg.get_nodes(kind="variable", name=child.name)
                              if n.id != child.id and n.file == child.file]
                    if not usages:
                        results.append(CPGQueryResult(
                            file=child.file,
                            line=child.line,
                            description=f"Variable '{child.name}' assigned but never used",
                            matched_nodes=[child.id],
                        ))
    return results


def query_dangerous_patterns_in_auth(cpg: CPG,
                                      auth_paths: List[str] = None) -> List[CPGQueryResult]:
    """Find dangerous patterns in auth-related code paths.

    Auth code should never:
      - Log passwords/tokens
      - Compare passwords with == (use constant-time comparison)
      - Use eval/exec
      - Skip authentication checks
    """
    if auth_paths is None:
        auth_paths = ["auth", "login", "session", "token", "password"]

    results: List[CPGQueryResult] = []
    # find functions whose name or file suggests auth context
    auth_functions: List[CPGNode] = []
    for func in cpg.get_nodes(kind="function"):
        if any(p in func.name.lower() for p in auth_paths) or \
           any(p in func.file.lower() for p in auth_paths):
            auth_functions.append(func)

    # for each auth function, check for dangerous patterns
    dangerous_calls = {"eval", "exec", "system", "Popen"}
    for func in auth_functions:
        # find all calls inside this function
        for kind, child_id in cpg.successors.get(func.id, []):
            if kind == "contains":
                child = cpg.nodes.get(child_id)
                if child and child.kind == "call" and child.name in dangerous_calls:
                    results.append(CPGQueryResult(
                        file=func.file,
                        line=child.line,
                        description=f"Dangerous call in auth function: {func.name}() calls {child.name}()",
                        matched_nodes=[func.id, child.id],
                        cwe="CWE-863",  # incorrect authorization
                    ))

    return results


def query_function_complexity(cpg: CPG, threshold: int = 10) -> List[CPGQueryResult]:
    """Find functions with high complexity (number of branches)."""
    results: List[CPGQueryResult] = []
    for func in cpg.get_nodes(kind="function"):
        # count branches inside this function
        branch_count = 0
        for kind, child_id in cpg.successors.get(func.id, []):
            if kind == "contains":
                child = cpg.nodes.get(child_id)
                if child and child.kind in ("if", "for", "while", "except"):
                    branch_count += 1
        if branch_count >= threshold:
            results.append(CPGQueryResult(
                file=func.file,
                line=func.line,
                description=f"High-complexity function: {func.name}() has {branch_count} branches",
                matched_nodes=[func.id],
                raw={"branches": branch_count, "function": func.name},
            ))
    return results


def _reconstruct_path(parent: Dict[str, str], source: str, sink: str) -> List[str]:
    """Reconstruct the path from source to sink using parent pointers."""
    path = [sink]
    cur = sink
    while cur != source:
        cur = parent.get(cur)
        if cur is None:
            break
        path.append(cur)
    path.reverse()
    return path


def _path_has_sanitizer(cpg: CPG, path: List[str], sanitizers: Set[str]) -> bool:
    """Check if any node in the path is a sanitizer call."""
    for nid in path:
        node = cpg.nodes.get(nid)
        if node and node.kind == "call" and node.name in sanitizers:
            return True
    return False
