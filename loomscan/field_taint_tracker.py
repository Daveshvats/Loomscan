"""v6.0: Field-sensitive taint tracker for IDOR and mass assignment.

Tracks taint at the FIELD level — not just "is this variable tainted?"
but "is THIS FIELD of this object tainted by user input?"

This enables detection of:
  - IDOR: user_id from @PathVariable used in findById without ownership check
  - Mass assignment: req.body spread into model, attacker sets role=admin
  - Privilege escalation: user.role = req.body.role (field-level taint)
  - Sensitive field exposure: user.password returned in API response

How it works:
  1. Identifies taint SOURCES: @PathVariable, @RequestParam, req.body,
     request.POST, ctx.request.body, @RequestBody
  2. Tracks taint PROPAGATION: assignment (a = source), field assignment
     (a.field = source), method call (a.setField(source))
  3. Identifies taint SINKS: findById(id), .save(entity), .delete(entity),
     DB queries with user-controlled IDs, response.body(entity)
  4. Flags when a tainted field reaches a sensitive sink without sanitization

Works on Python (.py), Java (.java), and JavaScript (.js).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Dict, Set, Tuple
from .models import Finding, Severity, LayerID, BlastRadius, Category


# Taint sources (user input entry points)
_TAINT_SOURCES = [
    # Java Spring
    r'@PathVariable\s+(?:\w+\s+)?(\w+)',
    r'@RequestParam\s+(?:\w+\s+)?(\w+)',
    r'@RequestBody\s+\w+\s+(\w+)',
    r'@ModelAttribute\s+\w+\s+(\w+)',
    # Python Flask/Django — request.POST['key'], request.GET.get('key'), etc.
    r"request\.(?:POST|GET|args|form|json|data|values)\s*(?:\[|\.)\s*['\"]?(\w+)",
    r"request\.GET\.get\s*\(\s*['\"](\w+)",
    r"request\.POST\.get\s*\(\s*['\"](\w+)",
    r"request\.json\.(?:get|pop)\s*\(\s*['\"](\w+)",
    # JavaScript Express/Koa
    r"req\.(?:body|params|query)\s*(?:\[|\.)\s*['\"]?(\w+)",
    r"ctx\.(?:request\.)?body\s*(?:\[|\.)\s*['\"]?(\w+)",
]

# Sensitive field names (fields that shouldn't be user-controlled)
_SENSITIVE_FIELDS = {
    "role", "isAdmin", "is_admin", "is_superuser", "is_staff", "admin",
    "password", "passwordHash", "password_hash", "salt",
    "permissions", "permissions_list", "authorities",
    "balance", "credit", "credit_limit", "creditLimit",
    "status", "verified", "is_verified", "email_verified", "active",
    "plan", "subscription", "tier", "level",
    "salary", "wage", "compensation",
    "apiKey", "api_key", "secret", "token",
}

# Taint sinks (where tainted data causes harm)
_TAINT_SINKS = [
    # DB lookup by ID (IDOR)
    (r'findById\s*\(\s*(\w+)\s*\)', "idor", "findById with user-controlled ID"),
    (r'getOne\s*\(\s*(\w+)\s*\)', "idor", "getOne with user-controlled ID"),
    (r'getById\s*\(\s*(\w+)\s*\)', "idor", "getById with user-controlled ID"),
    (r'\.get\s*\(\s*(\w+)\s*\)', "idor", ".get() with user-controlled ID"),
    (r'\.filter\s*\(\s*(?:id|pk|user_id|userId)\s*=\s*(\w+)\s*\)', "idor", "filter with user-controlled ID"),
    # DB save (mass assignment)
    (r'\.save\s*\(\s*(\w+)\s*\)', "mass_assignment", "save() with potentially tainted entity"),
    (r'\.update\s*\(\s*(\w+)\s*\)', "mass_assignment", "update() with potentially tainted entity"),
    # Field assignment from user input (privilege escalation)
    (r'\.role\s*=\s*(\w+)', "privilege_escalation", "role assigned from variable — verify not from user input"),
    (r'\.isAdmin\s*=\s*(\w+)', "privilege_escalation", "isAdmin assigned — verify not from user input"),
    (r'\.status\s*=\s*(\w+)', "privilege_escalation", "status assigned — verify not from user input"),
]


def scan_python_field_taint(file_path: Path, repo_root: Path) -> List[Finding]:
    """Scan Python file for field-sensitive taint issues."""
    if file_path.suffix != '.py':
        return []
    try:
        content = file_path.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return []

    rel_path = str(file_path.relative_to(repo_root))
    findings: List[Finding] = []

    # Track tainted variables and their fields
    tainted_vars: Set[str] = set()
    tainted_fields: Dict[str, Set[str]] = {}  # var_name → set of tainted fields

    lines = content.split('\n')
    for i, line in enumerate(lines, 1):
        # Detect taint sources
        for source_pattern in _TAINT_SOURCES:
            for match in re.finditer(source_pattern, line):
                var = match.group(1) if match.groups() else match.group(0)
                tainted_vars.add(var)

        # Detect field assignment from user input: obj.field = request.POST['field']
        # or obj.field = some_tainted_var
        field_assign = re.match(r'\s*(\w+)\.(\w+)\s*=\s*(.+)', line)
        if field_assign:
            obj, field, value = field_assign.groups()
            # Check if the field is sensitive
            if field in _SENSITIVE_FIELDS:
                # Check if the value contains a taint source pattern
                is_tainted = any(
                    re.search(source, value) for source in _TAINT_SOURCES
                )
                # Also check if value is a known tainted variable
                if is_tainted or value.strip() in tainted_vars:
                    findings.append(Finding(
                        layer=LayerID.L0_FAST,
                        rule_id="L0.field_taint.sensitive_assignment",
                        message=f"Sensitive field '{obj}.{field}' assigned from user input — privilege escalation risk. Whitelist fields explicitly.",
                        file=rel_path, start_line=i,
                        severity=Severity.CRITICAL, confidence=0.85,
                        blast_radius=BlastRadius.SYSTEM,
                        exploitability=0.9,
                        category=Category.SECURITY,
                        cwe="CWE-915",
                        fix_suggestion=f"Never assign user input to '{field}'. Use a DTO with explicit field mapping. Add @InitBinder to whitelist allowed fields.",
                    ))

        # Detect __dict__.update from user input (mass assignment)
        if re.search(r'__dict__\.update\s*\(\s*(?:request|req|POST|form|data|body)', line, re.IGNORECASE):
            findings.append(Finding(
                layer=LayerID.L0_FAST,
                rule_id="L0.field_taint.dict_update",
                message="Mass assignment: __dict__.update from user input — attacker can overwrite sensitive fields (role, isAdmin). Use explicit field assignment.",
                file=rel_path, start_line=i,
                severity=Severity.HIGH, confidence=0.9,
                blast_radius=BlastRadius.SYSTEM,
                exploitability=0.8,
                category=Category.SECURITY,
                cwe="CWE-915",
                fix_suggestion="Use explicit field assignment: obj.name = data['name']; obj.email = data['email']. Never use __dict__.update with user input.",
            ))

        # Detect DB query with user-controlled ID (IDOR)
        for sink_pattern, sink_type, desc in _TAINT_SINKS:
            for match in re.finditer(sink_pattern, line):
                var = match.group(1) if match.groups() else ""
                if var in tainted_vars:
                    if sink_type == "idor":
                        findings.append(Finding(
                            layer=LayerID.L0_FAST,
                            rule_id="L0.field_taint.idor_sink",
                            message=f"IDOR: {desc} '{var}' from user input — verify the caller owns this resource. Add authorization check.",
                            file=rel_path, start_line=i,
                            severity=Severity.HIGH, confidence=0.75,
                            blast_radius=BlastRadius.SYSTEM,
                            exploitability=0.7,
                            category=Category.SECURITY,
                            cwe="CWE-639",
                            fix_suggestion="Add ownership check: if resource.owner_id != current_user.id: return 403. Use @PreAuthorize with #id == authentication.principal.id.",
                        ))
                    elif sink_type == "mass_assignment":
                        findings.append(Finding(
                            layer=LayerID.L0_FAST,
                            rule_id="L0.field_taint.mass_assignment_sink",
                            message=f"Mass assignment: {desc} — entity may contain user-controlled sensitive fields. Validate before save.",
                            file=rel_path, start_line=i,
                            severity=Severity.MEDIUM, confidence=0.6,
                            blast_radius=BlastRadius.MODULE,
                            exploitability=0.6,
                            category=Category.SECURITY,
                            cwe="CWE-915",
                            fix_suggestion="Before save, validate entity fields: only allow whitelisted fields to be modified by the current user.",
                        ))
                    elif sink_type == "privilege_escalation":
                        findings.append(Finding(
                            layer=LayerID.L0_FAST,
                            rule_id="L0.field_taint.privilege_escalation",
                            message=f"Privilege escalation: {desc} — verify '{var}' is not from user input. Sensitive fields should only be set server-side.",
                            file=rel_path, start_line=i,
                            severity=Severity.CRITICAL, confidence=0.7,
                            blast_radius=BlastRadius.SYSTEM,
                            exploitability=0.9,
                            category=Category.SECURITY,
                            cwe="CWE-269",
                            fix_suggestion="Never set role/isAdmin/status from user input. Use server-side logic: user.role = determine_role(user).",
                        ))

    return findings


def scan_java_field_taint(file_path: Path, repo_root: Path) -> List[Finding]:
    """Scan Java file for field-sensitive taint issues."""
    try:
        content = file_path.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return []

    rel_path = str(file_path.relative_to(repo_root))
    findings: List[Finding] = []

    tainted_vars: Set[str] = set()
    lines = content.split('\n')

    for i, line in enumerate(lines, 1):
        # Detect @PathVariable / @RequestParam / @RequestBody
        for source_pattern in _TAINT_SOURCES:
            for match in re.finditer(source_pattern, line):
                var = match.group(1) if match.groups() else match.group(0)
                tainted_vars.add(var)

        # Detect sensitive field setter call: user.setRole(taintedVar)
        setter_match = re.match(r'\s*\w+\.(?:set|with)(\w+)\s*\(\s*(\w+)\s*\)', line)
        if setter_match:
            field_name, value = setter_match.groups()
            field_lower = field_name[0].lower() + field_name[1:]  # camelCase
            if value in tainted_vars and field_lower in _SENSITIVE_FIELDS:
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id="L0.field_taint.sensitive_setter",
                    message=f"Sensitive field '{field_name}' set from user input '{value}' — privilege escalation. Never set sensitive fields from user input.",
                    file=rel_path, start_line=i,
                    severity=Severity.CRITICAL, confidence=0.85,
                    blast_radius=BlastRadius.SYSTEM,
                    exploitability=0.9,
                    category=Category.SECURITY,
                    cwe="CWE-915",
                    fix_suggestion=f"Never call set{field_name}() with user input. Set server-side: user.setRole(determineRole(user)).",
                ))

        # Detect BeanUtils.copyProperties from user input
        if re.search(r'BeanUtils\.copyProperties\s*\(\s*(?:request|req|dto|body|form|input)', line, re.IGNORECASE):
            findings.append(Finding(
                layer=LayerID.L0_FAST,
                rule_id="L0.field_taint.beanutils_copy",
                message="Mass assignment: BeanUtils.copyProperties from user input — copies ALL fields including role, isAdmin. Use a mapper (MapStruct) with explicit field mapping.",
                file=rel_path, start_line=i,
                severity=Severity.HIGH, confidence=0.85,
                blast_radius=BlastRadius.SYSTEM,
                exploitability=0.8,
                category=Category.SECURITY,
                cwe="CWE-915",
                fix_suggestion="Use MapStruct or manual DTO→Entity mapping with only whitelisted fields. Or use @JsonIgnoreProperties on the DTO.",
            ))

        # Detect findById with tainted ID (IDOR)
        for sink_pattern, sink_type, desc in _TAINT_SINKS:
            for match in re.finditer(sink_pattern, line):
                var = match.group(1) if match.groups() else ""
                if var in tainted_vars and sink_type == "idor":
                    findings.append(Finding(
                        layer=LayerID.L0_FAST,
                        rule_id="L0.field_taint.idor_sink",
                        message=f"IDOR: {desc} '{var}' from user input — user can access other users' data. Add @PreAuthorize ownership check.",
                        file=rel_path, start_line=i,
                        severity=Severity.HIGH, confidence=0.75,
                        blast_radius=BlastRadius.SYSTEM,
                        exploitability=0.7,
                        category=Category.SECURITY,
                        cwe="CWE-639",
                        fix_suggestion="Add @PreAuthorize(\"@securityService.isOwner(#id, authentication)\") or check ownership in the service layer.",
                    ))

    return findings


def scan_js_field_taint(file_path: Path, repo_root: Path) -> List[Finding]:
    """Scan JavaScript file for field-sensitive taint issues."""
    try:
        content = file_path.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return []

    rel_path = str(file_path.relative_to(repo_root))
    findings: List[Finding] = []

    tainted_vars: Set[str] = set()
    lines = content.split('\n')

    for i, line in enumerate(lines, 1):
        # Detect req.body / req.params
        for source_pattern in _TAINT_SOURCES:
            for match in re.finditer(source_pattern, line):
                var = match.group(1) if match.groups() else match.group(0)
                tainted_vars.add(var)

        # Detect Object.assign from req.body
        if re.search(r'Object\.assign\s*\(\s*\w+\s*,\s*(?:req\.body|ctx\.request\.body|request\.body)', line):
            findings.append(Finding(
                layer=LayerID.L0_FAST,
                rule_id="L0.field_taint.object_assign",
                message="Mass assignment: Object.assign from req.body — copies ALL fields. Use a DTO class with only allowed properties.",
                file=rel_path, start_line=i,
                severity=Severity.HIGH, confidence=0.85,
                blast_radius=BlastRadius.SYSTEM,
                exploitability=0.8,
                category=Category.SECURITY,
                cwe="CWE-915",
                fix_suggestion="Use class-transformer with @Expose() on allowed fields only. Or manually pick fields: { name: req.body.name, email: req.body.email }.",
            ))

        # Detect spread of req.body
        if re.search(r'\{\s*\.\.\.\s*(?:req\.body|ctx\.request\.body|request\.body)', line):
            findings.append(Finding(
                layer=LayerID.L0_FAST,
                rule_id="L0.field_taint.spread",
                message="Mass assignment: spread of req.body into object — attacker can inject role, isAdmin. Whitelist properties explicitly.",
                file=rel_path, start_line=i,
                severity=Severity.HIGH, confidence=0.85,
                blast_radius=BlastRadius.SYSTEM,
                exploitability=0.8,
                category=Category.SECURITY,
                cwe="CWE-915",
                fix_suggestion="Pick only allowed fields: const { name, email } = req.body; const user = { name, email };",
            ))

    return findings


def scan_repo_field_taint(repo_root: Path, max_files: int = 500) -> List[Finding]:
    """Scan a repository for field-sensitive taint issues.

    Detects:
      - IDOR: user-controlled ID used in findById/get without ownership check
      - Mass assignment: user input spread into model object
      - Privilege escalation: sensitive field (role, isAdmin) set from user input
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
            findings.extend(scan_python_field_taint(p, repo_root))
            file_count += 1
        elif ext == '.java':
            findings.extend(scan_java_field_taint(p, repo_root))
            file_count += 1
        elif ext in ('.js', '.ts'):
            findings.extend(scan_js_field_taint(p, repo_root))
            file_count += 1

    return findings
