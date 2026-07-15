"""v6.0: TOCTOU (Time-of-Check to Time-of-Use) race condition detector.

Catches check-then-act patterns where a file/resource is checked (exists, isFile,
canRead) and then used (open, read, delete) in a separate call — the file could
be changed between check and use (symlink attack, privilege escalation).

Patterns detected:
  1. File TOCTOU: if os.path.exists(f): open(f)  — file could be swapped
  2. DB TOCTOU: if User.objects.filter(id=x).exists(): User.objects.get(id=x)
  3. Auth TOCTOU: if user.is_admin: do_admin_action()  — race on is_admin
  4. Lock TOCTOU: if not locked: locked=True; do_work()  — check-then-set race
  5. Cache TOCTOU: if key not in cache: cache[key] = expensive()  — stampede

Works on Python (.py), Java (.java), and JavaScript (.js) source files.
"""
from __future__ import annotations

import re
import ast
from pathlib import Path
from typing import List, Tuple, Set
from .models import Finding, Severity, LayerID, BlastRadius, Category


# =====================================================================
# Python AST-based TOCTOU detection (most accurate)
# =====================================================================

class TOCTOUVisitor(ast.NodeVisitor):
    """AST visitor that detects check-then-act patterns in Python."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.findings: List[Finding] = []
        self._check_vars: dict[str, int] = {}  # var_name → line where checked

    def visit_If(self, node: ast.If):
        """Detect check-then-act in if blocks."""
        # Analyze the test condition for "check" patterns
        check_info = self._analyze_check(node.test)
        if check_info:
            var_name, check_type, check_line = check_info
            # Look in the body for the "act" pattern
            for stmt in ast.walk(node):
                act_info = self._analyze_act(stmt, var_name, check_type)
                if act_info:
                    act_type, act_line = act_info
                    self.findings.append(Finding(
                        layer=LayerID.L0_FAST,
                        rule_id=f"L0.toctou.{check_type}_to_{act_type}",
                        message=self._build_message(check_type, act_type, var_name),
                        file=self.filepath, start_line=node.lineno,
                        severity=Severity.HIGH,
                        confidence=0.75,
                        blast_radius=BlastRadius.MODULE,
                        exploitability=0.6,
                        category=Category.SECURITY,
                        cwe="CWE-367",
                        fix_suggestion=self._get_fix(check_type, act_type),
                    ))
                    break  # One finding per if-block

        self.generic_visit(node)

    def _analyze_check(self, node) -> Tuple[str, str, int] | None:
        """Analyze if-condition for TOCTOU check patterns."""
        # os.path.exists(x) / os.path.isfile(x) / os.path.isdir(x)
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                # os.path.exists(file), os.access(file, F_OK)
                if isinstance(func.value, ast.Attribute):
                    if func.value.attr == 'path' and func.attr in ('exists', 'isfile', 'isdir', 'islink'):
                        if node.args:
                            var = self._get_var_name(node.args[0])
                            if var:
                                return (var, 'file_exists', node.lineno)
                # os.access(file, mode)
                if func.attr == 'access' and isinstance(func.value, ast.Name) and func.value.id == 'os':
                    if node.args:
                        var = self._get_var_name(node.args[0])
                        if var:
                            return (var, 'file_access', node.lineno)
                # file.exists() (Django/SQLAlchemy queryset)
                if func.attr == 'exists' and isinstance(func.value, ast.Call):
                    return ('queryset', 'db_exists', node.lineno)
                # dict.__contains__ (key in cache)
                if func.attr == '__contains__':
                    return ('cache_key', 'cache_check', node.lineno)
            # isinstance(obj, type) check
            if isinstance(func, ast.Name) and func.id == 'isinstance':
                return ('type_check', 'isinstance', node.lineno)

        # Comparison: user.is_admin == True, user.role == 'admin'
        if isinstance(node, ast.Compare):
            left_var = self._get_var_name(node.left)
            if left_var:
                # user.is_admin, user.role, user.has_permission
                if any(attr in left_var for attr in ('is_admin', 'is_superuser', 'has_permission', 'role', 'is_staff')):
                    return (left_var, 'auth_check', node.lineno)

        # "x not in cache" or "x not in dict"
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            if isinstance(node.ops[0], (ast.NotIn, ast.In)):
                return ('cache_key', 'cache_check', node.lineno)

        return None

    def _analyze_act(self, node, var_name: str, check_type: str) -> Tuple[str, int] | None:
        """Analyze if-body for TOCTOU act patterns."""
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                # open(file)
                if func.id == 'open' and check_type in ('file_exists', 'file_access'):
                    return ('file_open', node.lineno)
            if isinstance(func, ast.Attribute):
                # file.read(), file.write(), file.delete()
                if func.attr in ('read', 'write', 'delete', 'unlink', 'remove', 'rmdir') and check_type in ('file_exists', 'file_access'):
                    return ('file_use', node.lineno)
                # queryset.get(), queryset.filter().first()
                if func.attr in ('get', 'first', 'create', 'update', 'delete') and check_type == 'db_exists':
                    return ('db_use', node.lineno)
                # cache[key] = value, cache.set(key, value)
                if func.attr == 'set' and check_type == 'cache_check':
                    return ('cache_set', node.lineno)
        # Assignment: cache[key] = value
        if isinstance(node, ast.Assign) and check_type == 'cache_check':
            return ('cache_set', getattr(node, 'lineno', 0))
        return None

    def _get_var_name(self, node) -> str | None:
        """Extract variable name from AST node."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = self._get_var_name(node.value)
            if parent:
                return f"{parent}.{node.attr}"
        if isinstance(node, ast.Constant):
            return str(node.value)
        return None

    def _build_message(self, check_type: str, act_type: str, var: str) -> str:
        messages = {
            ('file_exists', 'file_open'): f"TOCTOU race: os.path.exists({var}) checked then open({var}) — file could be swapped between check and use (symlink attack). Use try/except OSError instead.",
            ('file_exists', 'file_use'): f"TOCTOU race: os.path.exists({var}) checked then file operation — file could be swapped. Use try/except instead of check-then-act.",
            ('file_access', 'file_open'): f"TOCTOU race: os.access({var}) checked then open({var}) — permission could change. Use try/except.",
            ('db_exists', 'db_use'): f"TOCTOU race: .exists() checked then .get()/.first() — record could be deleted between check and use. Use try/except DoesNotExist.",
            ('auth_check', 'auth_check'): f"TOCTOU race: auth attribute checked then used — user role could change between check and action. Re-check inside critical section.",
            ('cache_check', 'cache_set'): f"TOCTOU race: cache miss check then set — multiple threads may compute and set simultaneously (cache stampede). Use threading.Lock or atomic setnx.",
        }
        return messages.get((check_type, act_type), f"TOCTOU race condition: {check_type} then {act_type} on {var}")

    def _get_fix(self, check_type: str, act_type: str) -> str:
        fixes = {
            ('file_exists', 'file_open'): "Use EAFP (Easier to Ask Forgiveness): try: f = open(path) except FileNotFoundError: ...",
            ('file_exists', 'file_use'): "Use try/except instead of if-exists-then-use. The file could be swapped between check and use.",
            ('db_exists', 'db_use'): "Use try: obj = Model.objects.get(id=x) except Model.DoesNotExist: ... instead of if .exists(): .get()",
            ('cache_check', 'cache_set'): "Use cache.get_or_set() (atomic) or threading.Lock to prevent cache stampede.",
        }
        return fixes.get((check_type, act_type), "Use EAFP pattern (try/except) instead of LBYL (look before you leap).")


def scan_python_toctou(file_path: Path, repo_root: Path) -> List[Finding]:
    """Scan a Python file for TOCTOU race conditions using AST analysis."""
    if file_path.suffix != '.py':
        return []
    try:
        source = file_path.read_text(encoding='utf-8', errors='replace')
        tree = ast.parse(source)
    except Exception:
        return []

    rel_path = str(file_path.relative_to(repo_root))
    visitor = TOCTOUVisitor(rel_path)
    visitor.visit(tree)
    return visitor.findings


# =====================================================================
# Regex-based TOCTOU detection for Java and JavaScript
# =====================================================================

# Java TOCTOU patterns (line-based, since we don't parse Java AST)
_JAVA_TOCTOU_PATTERNS: List[Tuple[str, str, Severity, str, str]] = [
    # File exists → File use
    (r'if\s*\(\s*Files\.exists\s*\(\s*(\w+)\s*\)\s*\)\s*\{[^}]*Files\.(?:readAllBytes|write|delete|copy|move)\s*\(\s*\1',
     "java.toctou.file_exists",
     Severity.HIGH,
     "TOCTOU race: Files.exists() then Files.read/write/delete — file could be swapped. Use try/catch NoSuchFileException.",
     "CWE-367"),
    # DB exists → DB get
    (r'if\s*\(\s*\w+Repository\.existsById\s*\(\s*(\w+)\s*\)\s*\)\s*\{[^}]*\.findById\s*\(\s*\1',
     "java.toctou.db_exists",
     Severity.MEDIUM,
     "TOCTOU race: existsById() then findById() — record could be deleted between check and use. Use orElseThrow() instead.",
     "CWE-367"),
    # Auth check → action
    (r'if\s*\(\s*\w+\.is(?:Admin|SuperUser|Staff|Manager)\s*\(\s*\)\s*\)\s*\{',
     "java.toctou.auth_check",
     Severity.MEDIUM,
     "TOCTOU risk: auth check then action — user role could change between check and action. Use @PreAuthorize for atomic authorization.",
     "CWE-367"),
    # Cache check → cache put
    (r'if\s*\(\s*!\w+\.containsKey\s*\(\s*(\w+)\s*\)\s*\)\s*\{[^}]*\.put\s*\(\s*\1',
     "java.toctou.cache_check",
     Severity.MEDIUM,
     "TOCTOU race: containsKey() then put() — cache stampede. Use computeIfAbsent() for atomic check-and-set.",
     "CWE-367"),
    # Map check → map put (race condition)
    (r'if\s*\(\s*!\w+\.containsKey\s*\(\s*(\w+)\s*\)\s*\)\s*\{[^}]*\.\w+\.put\s*\(',
     "java.toctou.map_check",
     Severity.LOW,
     "TOCTOU race: containsKey check then put — use putIfAbsent() or computeIfAbsent() for thread-safe check-and-set.",
     "CWE-367"),
]

_JS_TOCTOU_PATTERNS: List[Tuple[str, str, Severity, str, str]] = [
    # fs.exists → fs operation (deprecated in Node.js for this reason)
    (r'if\s*\(\s*fs\.existsSync\s*\(\s*(\w+)\s*\)\s*\)\s*\{[^}]*fs\.(?:readFile|writeFile|unlink|stat|createReadStream)',
     "js.toctou.fs_exists",
     Severity.HIGH,
     "TOCTOU race: fs.existsSync() then fs operation — file could be swapped. Use try/catch with fs.promises.",
     "CWE-367"),
    # Cache check → cache set
    (r'if\s*\(\s*!\w+\.has\s*\(\s*(\w+)\s*\)\s*\)\s*\{[^}]*\.set\s*\(\s*\1',
     "js.toctou.cache_check",
     Severity.MEDIUM,
     "TOCTOU race: Map.has() then Map.set() — race condition in concurrent contexts. Use atomic operations.",
     "CWE-367"),
    # DB check → DB use
    (r'if\s*\(\s*await\s+\w+\.findOne\s*\(\s*\{[^}]*\}\s*\)\s*\)\s*\{',
     "js.toctou.db_findone",
     Severity.MEDIUM,
     "TOCTOU race: findOne() check then use — record could change between check and action. Use atomic operations.",
     "CWE-367"),
]


def scan_java_toctou(file_path: Path, repo_root: Path) -> List[Finding]:
    """Scan a Java file for TOCTOU race conditions using regex."""
    return _scan_regex_toctou(file_path, repo_root, _JAVA_TOCTOU_PATTERNS)


def scan_js_toctou(file_path: Path, repo_root: Path) -> List[Finding]:
    """Scan a JavaScript file for TOCTOU race conditions using regex."""
    return _scan_regex_toctou(file_path, repo_root, _JS_TOCTOU_PATTERNS)


def _scan_regex_toctou(file_path: Path, repo_root: Path,
                       patterns: List[Tuple[str, str, Severity, str, str]]) -> List[Finding]:
    """Scan a file using regex patterns for TOCTOU."""
    try:
        content = file_path.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return []

    rel_path = str(file_path.relative_to(repo_root))
    findings: List[Finding] = []

    # TOCTOU patterns span multiple lines, so we search the full content
    for pattern, rule_id, severity, message, cwe in patterns:
        matches = re.finditer(pattern, content, re.MULTILINE | re.DOTALL)
        for match in matches:
            line_num = content[:match.start()].count('\n') + 1
            findings.append(Finding(
                layer=LayerID.L0_FAST,
                rule_id=f"L0.{rule_id}",
                message=message,
                file=rel_path, start_line=line_num,
                severity=severity, confidence=0.7,
                blast_radius=BlastRadius.MODULE,
                exploitability=0.5,
                category=Category.SECURITY,
                cwe=cwe,
                fix_suggestion="Use EAFP pattern: try the operation directly and handle the exception if it fails.",
            ))

    return findings


# =====================================================================
# Main entry point
# =====================================================================

def scan_repo_toctou(repo_root: Path, max_files: int = 500) -> List[Finding]:
    """Scan a repository for TOCTOU race conditions.

    Detects check-then-act patterns in Python, Java, and JavaScript:
      - File TOCTOU: if exists(f): open(f) → symlink attack
      - DB TOCTOU: if .exists(): .get() → record deleted between check and use
      - Auth TOCTOU: if user.is_admin: action() → role changed between check and action
      - Cache TOCTOU: if key not in cache: cache[key] = compute() → cache stampede
      - Map TOCTOU: if !map.containsKey(k): map.put(k, v) → race condition
    """
    findings: List[Finding] = []
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                 "build", "dist", "target", ".loomscan-cache"}

    file_count = 0
    for p in repo_root.rglob("*"):
        if file_count >= max_files:
            break
        if not p.is_file():
            continue
        if any(part in skip_dirs for part in p.parts):
            continue

        ext = p.suffix.lower()
        if ext == '.py':
            findings.extend(scan_python_toctou(p, repo_root))
            file_count += 1
        elif ext == '.java':
            findings.extend(scan_java_toctou(p, repo_root))
            file_count += 1
        elif ext in ('.js', '.ts'):
            findings.extend(scan_js_toctou(p, repo_root))
            file_count += 1

    return findings
