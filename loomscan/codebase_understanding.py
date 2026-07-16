from __future__ import annotations

import ast
import re
import os
import json
import subprocess
import sys
import textwrap
import tempfile
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

try:
    from .normalized_ast import parse_file, get_language, is_supported, NormalizedNode, _HAS_TS, _TS_LANGUAGE_MODULES
except ImportError:
    _HAS_TS = False
    _TS_LANGUAGE_MODULES = {}

_v4_logger = logging.getLogger("loomscan.v4_restored")

@dataclass
class FunctionBehavior:
    name: str
    file: str
    line: int
    language: str
    params: List[str] = field(default_factory=list)
    calls: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    modifies: List[str] = field(default_factory=list)
    reads: List[str] = field(default_factory=list)
    hardcoded_values: List[Tuple[str, int]] = field(default_factory=list)
    has_auth: bool = False
    has_db_write: bool = False
    has_external: bool = False
    # v7.3: entity-type tracking for dead-persistence detection
    entity_types_written: List[str] = field(default_factory=list)
    entity_types_read: List[str] = field(default_factory=list)

@dataclass
class ConfigEntry:
    key: str
    value: str
    file: str
    line: int

@dataclass
class CodebaseModel:
    functions: List[FunctionBehavior] = field(default_factory=list)
    config_entries: List[ConfigEntry] = field(default_factory=list)
    api_endpoints_used: Dict[str, List[str]] = field(default_factory=dict)

SAFE_CONSTANTS = {0, 1, -1, 2, 200, 201, 204, 301, 302, 400, 401, 403, 404, 500, 80, 443, 22, 5432, 3306, 6379, 27017, 60, 3600, 86400}


# =============================================================================
# v7.3: Entity-type tracking for dead-persistence detection.
# =============================================================================

# Method-call patterns that indicate a DB WRITE of an entity (persist/save/insert/update)
_DB_WRITE_METHODS = {
    "save", "saveAll", "persist", "merge", "insert", "insertAll",
    "update", "updateAll", "bulkInsert", "add",
}

# Method-call patterns that indicate a DB READ of an entity (find/get/query/list)
_DB_READ_METHODS = {
    "find", "findById", "findAll", "findAllById", "findOne", "findByName",
    "findByEmail", "findByUsername", "findByCode", "findByKey", "findBySlug",
    "getById", "getOne", "getReferenceById", "existsById", "count",
    "query", "createQuery", "createNativeQuery", "list", "iterate",
    "getById", "get", "select",
}


def _infer_entity_type_from_call(method_name: str, args_text: str = "") -> Optional[str]:
    """Given a DB write/read method name and its argument text, infer the entity type.

    Examples:
        save(user)              -> "user"
        save(new User(...))     -> "User"
        persist(entity)         -> "entity"
        findById(id)            -> None  (can't tell from id alone)
        findAll(User.class)     -> "User"
    """
    if not method_name:
        return None
    # Try to extract from `new TypeName(...)` argument
    m = re.search(r'\bnew\s+([A-Z]\w*)\s*\(', args_text)
    if m:
        return m.group(1)
    # Try to extract from `TypeName.class` argument
    m = re.search(r'\b([A-Z]\w*)\.class\b', args_text)
    if m:
        return m.group(1)
    # Try to extract from the first variable arg (heuristic: lowercase = entity var)
    m = re.match(r'\s*([a-z]\w*)\b', args_text)
    if m and m.group(1) not in {"id", "ids", "ids", "true", "false", "null"}:
        return m.group(1)
    return None


# Repository naming convention: typically `<EntityName>Repository` / `<EntityName>Repo` / `<EntityName>Dao`
_REPO_NAME_RE = re.compile(r'\b([A-Z]\w*?)(?:Repository|Repo|Dao|Mapper)\b')

# Spring Data `@Entity(name="X")` annotation
_ENTITY_NAME_RE = re.compile(r'@Entity\s*\(\s*(?:name\s*=\s*)?["\']([A-Z]\w*)["\']')


def _index_entity_writes_reads(source: str, func: FunctionBehavior) -> None:
    """Populate `entity_types_written` and `entity_types_read` on a FunctionBehavior.

    Scans for DB-write and DB-read method calls and infers the entity type from
    arguments or the surrounding repository variable name.
    """
    # Map of all repository-style variables seen in the function: varname -> EntityName
    repo_var_to_entity: Dict[str, str] = {}
    for m in _REPO_NAME_RE.finditer(source):
        repo_var_to_entity[m.group(0)] = m.group(1)
    # Also pick up `XRepository y` declarations
    for m in re.finditer(r'\b([A-Z]\w*?)(?:Repository|Repo|Dao)\s+(\w+)\s*[=;]', source):
        entity, var = m.group(1), m.group(2)
        repo_var_to_entity[var] = entity

    # Find write calls: `repoVar.save(...)`, `em.persist(...)`, etc.
    write_pat = re.compile(r'\b(\w+)\.(' + '|'.join(_DB_WRITE_METHODS) + r')\s*\(([^)]*)\)')
    for m in write_pat.finditer(source):
        receiver, method, args = m.group(1), m.group(2), m.group(3)
        entity = _infer_entity_type_from_call(method, args)
        if not entity:
            # Fall back to the receiver variable's type
            entity = repo_var_to_entity.get(receiver)
        if entity:
            func.entity_types_written.append(entity)
            func.has_db_write = True

    # Find read calls: `repoVar.findById(...)`, `repoVar.findAll(...)`, etc.
    read_pat = re.compile(r'\b(\w+)\.(' + '|'.join(_DB_READ_METHODS) + r')\s*\(([^)]*)\)')
    for m in read_pat.finditer(source):
        receiver, method, args = m.group(1), m.group(2), m.group(3)
        entity = _infer_entity_type_from_call(method, args)
        if not entity:
            entity = repo_var_to_entity.get(receiver)
        if entity:
            func.entity_types_read.append(entity)


def detect_dead_persistence(model: "CodebaseModel") -> List["UnifiedFinding"]:
    """Detect entities that are written to the DB but never read anywhere.

    A "dead entity" is one that appears in `entity_types_written` of any function
    but never appears in `entity_types_read` of ANY function in the codebase.
    These represent wasted persistence — data is stored but never queried, which
    wastes DB space, write I/O, and indexing overhead.

    Returns findings of rule_id `CU.DB-DEAD-PERSISTENCE`.
    """
    all_written: Dict[str, List[Tuple[str, int, str]]] = defaultdict(list)
    all_read: Set[str] = set()

    for func in model.functions:
        for entity in func.entity_types_written:
            all_written[entity].append((func.file, func.line, func.name))
        all_read.update(func.entity_types_read)

    findings: List[UnifiedFinding] = []
    # Don't flag ultra-generic names — too many false positives
    _GENERIC_NAMES = {"entity", "obj", "object", "data", "item", "value", "model", "dto", "vo"}
    for entity, occurrences in all_written.items():
        if entity.lower() in _GENERIC_NAMES:
            continue
        if entity in all_read:
            continue
        # Skip entities that appear < 2 times — single occurrence may be a fluke
        if len(occurrences) < 2:
            continue
        first_file, first_line, first_func = occurrences[0]
        findings.append(UnifiedFinding(
            rule_id="CU.DB-DEAD-PERSISTENCE",
            severity="low",
            description=(
                f"Entity '{entity}' is written to the DB in {len(occurrences)} place(s) "
                f"but never read anywhere in the codebase — dead persistence. "
                f"Either remove the write path, or add a read path (the data may be unused)."
            ),
            file=first_file,
            line=first_line,
            function=first_func,
            language="unknown",
            category="dead_persistence",
            suggestion=(
                f"Verify whether '{entity}' should have a read path. If not, remove the save()/persist() "
                "calls to avoid wasting DB writes, storage, and index maintenance. If yes, add a "
                f"repository.find...() method and call it where the data is needed."
            ),
            cwe="CWE-400",
        ))
    return findings


def index_codebase(repo_root: Path, max_files=300) -> CodebaseModel:
    model = CodebaseModel()
    skip = {".git", "__pycache__", ".venv", "venv", "node_modules", ".loomscan-cache", "build", "dist", "target", ".pytest_cache"}
    count = 0
    for f in sorted(repo_root.rglob("*")):
        if not f.is_file() or any(p in skip for p in f.parts):
            continue
        ext = f.suffix.lower()
        if ext == ".py" and count < max_files:
            count += 1
            _index_py_file(f, repo_root, model)
        elif ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".java", ".c", ".cpp", ".rs") and count < max_files:
            count += 1
            _index_multi_file(f, repo_root, model)
        # Config files
        if ext in (".yaml", ".yml", ".json", ".env", ".ini", ".cfg", ".toml", ".properties") or f.name in (".env", ".env.local", "settings.py", "config.js", "config.json"):
            _index_config(f, repo_root, model)
    return model

def _index_py_file(fp, root, model):
    try:
        source = fp.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        return
    rel = str(fp.relative_to(root)) if root in fp.parents or str(root) in str(fp) else str(fp)
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        func = FunctionBehavior(name=node.name, file=rel, line=node.lineno, language="python")
        func.params = [a.arg for a in node.args.args if a.arg != "self"]
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                cn = sub.func.id if isinstance(sub.func, ast.Name) else (sub.func.attr if isinstance(sub.func, ast.Attribute) else "")
                if cn: func.calls.append(cn)
                if cn in ("execute", "executemany", "insert", "update", "delete", "save", "commit"): func.has_db_write = True
                if any(k in cn.lower() for k in ("check_auth", "require_auth", "is_authenticated", "current_user", "verify_token")): func.has_auth = True
                if any(k in cn.lower() for k in ("callback", "notify", "emit", "send", "publish")): func.has_external = True
                if cn in ("post", "get", "put", "delete", "patch", "fetch") and sub.args:
                    url_arg = sub.args[0]
                    url_text = str(url_arg.value) if isinstance(url_arg, ast.Constant) else (ast.unparse(url_arg) if hasattr(ast, "unparse") else "")
                    if url_text and ("/api/" in url_text or "/v1/" in url_text):
                        func.api_endpoints.append(url_text)
                        model.api_endpoints_used.setdefault(url_text, []).append(node.name)
            if isinstance(sub, ast.Assign):
                for t in sub.targets:
                    if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == "self":
                        func.modifies.append(t.attr)
            if isinstance(sub, ast.Compare):
                for c in sub.comparators:
                    if isinstance(c, ast.Constant) and isinstance(c.value, (int, float)) and c.value not in SAFE_CONSTANTS:
                        if isinstance(c.value, int) and not (-4 <= c.value <= 4):
                            func.hardcoded_values.append((str(c.value), sub.lineno))
        # v7.3: entity-type tracking for dead-persistence detection
        func_source = ast.get_source_segment(source, node) or ""
        _index_entity_writes_reads(func_source, func)
        model.functions.append(func)

def _index_multi_file(fp, root, model):
    try:
        source = fp.read_text(encoding="utf-8")
    except Exception:
        return
    # Determine language: prefer tree-sitter detection, fall back to file extension
    if _HAS_TS:
        lang = get_language(fp)
    else:
        # Extension-based fallback when tree-sitter is not available
        ext = fp.suffix.lower()
        _EXT_LANG = {
            ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
            ".ts": "typescript", ".tsx": "typescript",
            ".go": "go", ".java": "java", ".kt": "java",
            ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp",
            ".rs": "rust",
        }
        lang = _EXT_LANG.get(ext, "unknown")
    if lang == "unknown":
        return
    rel = str(fp.relative_to(root)) if root in fp.parents or str(root) in str(fp) else str(fp)
    lines = source.splitlines()
    func_pats = {"javascript": re.compile(r'function\s+(\w+)\s*\(([^)]*)\)'), "typescript": re.compile(r'function\s+(\w+)\s*\(([^)]*)\)'), "go": re.compile(r'func\s+(?:\([^)]*\)\s+)?(\w+)\s*\(([^)]*)\)'), "java": re.compile(r'(?:public|private|protected|static)\s+\w+\s+(\w+)\s*\(([^)]*)\)'), "c": re.compile(r'\w+\s+(\w+)\s*\([^)]*\)\s*\{'), "cpp": re.compile(r'\w+\s+(\w+)\s*\([^)]*\)\s*\{'), "rust": re.compile(r'fn\s+(\w+)\s*\(([^)]*)\)')}
    pat = func_pats.get(lang)
    if not pat: return
    cur = None
    cur_start_line = 0
    cur_lines: List[str] = []
    for i, line in enumerate(lines, 1):
        m = pat.search(line)
        if m:
            # Flush the previous function: run entity-write/read indexing on its source
            if cur:
                cur_source = "\n".join(cur_lines)
                _index_entity_writes_reads(cur_source, cur)
                model.functions.append(cur)
            cur = FunctionBehavior(name=m.group(1), file=rel, line=i, language=lang)
            cur_start_line = i
            cur_lines = [line]
        else:
            if cur is not None:
                cur_lines.append(line)
        if not cur: continue
        s = line.strip()
        for mm in re.finditer(r'\.(\w+)\s*\(', s):
            method = mm.group(1)
            cur.calls.append(method)
            if method in ("execute", "executemany", "insert", "update", "delete", "save", "commit", "Exec", "Execute"): cur.has_db_write = True
            if any(k in method.lower() for k in ("notify", "emit", "send", "publish", "dispatch")): cur.has_external = True
        for mm in re.finditer(r'["\'](/(?:api|v\d+)/[^\s"\']+)["\']', s, re.IGNORECASE):
            cur.api_endpoints.append(mm.group(1))
            model.api_endpoints_used.setdefault(mm.group(1), []).append(cur.name)
        for mm in re.finditer(r'\bif\s*\(?[\w\.\[\]]+\s*[<>=!]+\s*(\d+(?:\.\d+)?)', s, re.IGNORECASE):
            try:
                v = int(mm.group(1)) if "." not in mm.group(1) else float(mm.group(1))
                if v not in SAFE_CONSTANTS and isinstance(v, int) and not (-4 <= v <= 4):
                    cur.hardcoded_values.append((mm.group(1), i))
            except Exception as e: _v4_logger.debug('suppressed: %s', e)
    # Flush last function
    if cur:
        cur_source = "\n".join(cur_lines)
        _index_entity_writes_reads(cur_source, cur)
        model.functions.append(cur)

def _index_config(fp, root, model):
    try:
        text = fp.read_text(encoding="utf-8")
    except Exception:
        return
    rel = str(fp.relative_to(root)) if root in fp.parents or str(root) in str(fp) else str(fp)
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith(("#", "//", "[", "/*", "*")): continue
        m = re.match(r'^(\w[\w._-]*)\s*[:=]\s*(.+?)\s*$', s)
        if m:
            key, val = m.group(1).lower(), m.group(2).strip().strip('"\'')
            if val and not val.startswith("$") and not val.startswith("{"):
                model.config_entries.append(ConfigEntry(key=key, value=val, file=rel, line=i))

def analyze_codebase(repo_root: Path) -> Tuple[CodebaseModel, List[UnifiedFinding]]:
    model = index_codebase(repo_root)
    findings: List[UnifiedFinding] = []
    # 1. Hardcoded values that exist in config
    config_vals = {e.value: e for e in model.config_entries}
    for func in model.functions:
        for val, line in func.hardcoded_values:
            if val in config_vals:
                ce = config_vals[val]
                findings.append(UnifiedFinding(
                    rule_id="CU.HARDCODED-IN-CONFIG", severity="high",
                    description=f"Value {val} hardcoded in '{func.name}()' but exists in config {ce.file}:{ce.line} (key: '{ce.key}')",
                    file=func.file, line=line, function=func.name, language=func.language,
                    category="hardcoded_value", suggestion=f"Read from config['{ce.key}']", cwe="CWE-733"))
    # 2. DB write without auth (behavioral, not name-based)
    for func in model.functions:
        if func.has_db_write and not func.has_auth:
            findings.append(UnifiedFinding(
                rule_id="CU.DB-WRITE-WITHOUT-AUTH", severity="high",
                description=f"'{func.name}()' writes to DB without auth check",
                file=func.file, line=func.line, function=func.name, language=func.language,
                category="behavioral", suggestion="Add auth check", cwe="CWE-862"))
    # 3. External call + DB write (reentrancy)
    for func in model.functions:
        if func.has_external and func.has_db_write:
            findings.append(UnifiedFinding(
                rule_id="CU.EXTERNAL-PLUS-DB-WRITE", severity="medium",
                description=f"'{func.name}()' makes external call AND writes to DB — verify order (reentrancy)",
                file=func.file, line=func.line, function=func.name, language=func.language,
                category="behavioral", suggestion="Ensure DB write before external call", cwe="CWE-836"))
    # 4. State written but never read
    all_reads = set()
    for f in model.functions: all_reads.update(f.reads)
    for f in model.functions:
        for var in f.modifies:
            if var not in all_reads and var not in ("result", "tmp", "temp", "data", "output"):
                findings.append(UnifiedFinding(
                    rule_id="CU.WRITE-WITHOUT-READ", severity="low",
                    description=f"State '{var}' written in '{f.name}()' but never read",
                    file=f.file, line=f.line, function=f.name, language=f.language,
                    category="behavioral", suggestion="Check if read is missing", cwe="CWE-563"))
                break
    # 5. v7.3: Dead persistence — entities written but never read anywhere
    findings.extend(detect_dead_persistence(model))
    return model, findings


# =============================================================================
# 3. SEMANTIC BL (hardcoded values, API mismatches) — all languages
# =============================================================================

ENDPOINT_KEYWORDS = {
    "create": ["create", "add", "insert", "new", "store", "save"],
    "update": ["update", "edit", "modify", "change", "set", "patch"],
    "delete": ["delete", "remove", "destroy", "drop", "clear"],
    "get": ["get", "fetch", "retrieve", "find", "search", "list", "read"],
    "reschedule": ["reschedule", "move", "rebook"],
    "cancel": ["cancel", "void", "abort"],
    "approve": ["approve", "accept", "confirm"],
    "reject": ["reject", "decline", "deny"],
    "login": ["login", "signin", "authenticate"],
    "logout": ["logout", "signout"],
    "register": ["register", "signup", "enroll"],
    "submit": ["submit", "send", "post"],
    "verify": ["verify", "validate", "check"],
    "reset": ["reset", "clear", "purge"],
    "assign": ["assign", "allocate", "designate"],
    "transfer": ["transfer", "move", "send"],
    "refund": ["refund", "reimburse", "return"],
    "charge": ["charge", "bill", "invoice"],
}

def _extract_endpoint(url):
    ep = url
    if "://" in ep: ep = "/" + ep.split("/", 3)[3] if ep.count("/") >= 3 else "/"
    if not ep.startswith("/"): ep = "/" + ep
    ep = ep.split("?")[0]
    ep = re.sub(r'\{[^}]+\}', '', ep)
    return ep

def _check_endpoint_mismatch(func_name, endpoint):
    ep_parts = endpoint.lower().strip("/").split("/")
    ep_action = None
    for part in ep_parts:
        for kw in ENDPOINT_KEYWORDS:
            if kw in part: ep_action = kw; break
        if ep_action: break
    if not ep_action: return None
    func_action = None
    for kw, syns in ENDPOINT_KEYWORDS.items():
        for s in syns:
            if s in func_name.lower(): func_action = kw; break
        if func_action: break
    if not func_action: return None
    if func_action != ep_action:
        if ep_action not in ENDPOINT_KEYWORDS.get(func_action, []) and func_action not in ENDPOINT_KEYWORDS.get(ep_action, []):
            return f"Function '{func_name}' suggests '{func_action}' but endpoint is '{ep_action}' — may not support needed fields"
    return None

def detect_semantic_bl(file_path: Path) -> List[UnifiedFinding]:
    try:
        source = file_path.read_text(encoding="utf-8")
    except Exception:
        return []
    lang = get_language(file_path) if _HAS_TS else "python"
    if lang == "unknown": return []
    findings = []
    lines = source.splitlines()
    cur_func = ""
    func_pats = {"python": re.compile(r'def\s+(\w+)\s*\('), "javascript": re.compile(r'function\s+(\w+)\s*\('), "typescript": re.compile(r'function\s+(\w+)\s*\('), "go": re.compile(r'func\s+(?:\([^)]*\)\s+)?(\w+)\s*\('), "java": re.compile(r'(?:public|private|protected|static)\s+\w+\s+(\w+)\s*\('), "c": re.compile(r'\w+\s+(\w+)\s*\([^)]*\)\s*\{'), "cpp": re.compile(r'\w+\s+(\w+)\s*\([^)]*\)\s*\{'), "rust": re.compile(r'fn\s+(\w+)\s*\(')}
    pat = func_pats.get(lang, func_pats["python"])
    for i, line in enumerate(lines, 1):
        m = pat.search(line)
        if m: cur_func = m.group(1)
        s = line.strip()
        if not s or s.startswith(("#", "//", "/*", "*", "--")): continue
        # Hardcoded thresholds
        for mm in re.finditer(r'\bif\s*\(?[\w\.\[\]]+\s*[<>=!]+\s*(\d+(?:\.\d+)?)', s, re.IGNORECASE):
            v = float(mm.group(1)) if "." in mm.group(1) else int(mm.group(1))
            if v not in SAFE_CONSTANTS and isinstance(v, int) and not (-4 <= v <= 4):
                findings.append(UnifiedFinding(rule_id="SEM.HARDCODED-THRESHOLD", severity="medium",
                    description=f"Hardcoded threshold {v} in condition — consider config/env",
                    file=str(file_path), line=i, function=cur_func, language=lang,
                    category="hardcoded_value", suggestion=f"Move {v} to config"))
        # Hardcoded URLs
        for mm in re.finditer(r'["\'](https?://[^\s"\']+)["\']', s):
            url = mm.group(1)
            if not any(x in url.lower() for x in ("example.com", "schema.org", "w3.org", "localhost")):
                findings.append(UnifiedFinding(rule_id="SEM.HARDCODED-URL", severity="medium",
                    description=f"Hardcoded URL '{url}'", file=str(file_path), line=i,
                    function=cur_func, language=lang, category="hardcoded_value", suggestion="Use config"))
        # Hardcoded API paths
        for mm in re.finditer(r'["\'](/(?:api|v\d+)/[^\s"\']+)["\']', s, re.IGNORECASE):
            path = mm.group(1)
            findings.append(UnifiedFinding(rule_id="SEM.HARDCODED-API-PATH", severity="low",
                description=f"Hardcoded API path '{path}'", file=str(file_path), line=i,
                function=cur_func, language=lang, category="hardcoded_value", suggestion="Centralize API paths"))
            # Check endpoint mismatch
            if cur_func:
                mismatch = _check_endpoint_mismatch(cur_func, path)
                if mismatch:
                    findings.append(UnifiedFinding(rule_id="SEM.API-MISMATCH", severity="high",
                        description=mismatch, file=str(file_path), line=i, function=cur_func,
                        language=lang, category="api_mismatch", suggestion="Check if endpoint supports needed fields"))
    return findings

from .v4_types import UnifiedFinding
