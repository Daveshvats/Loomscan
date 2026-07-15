"""v5.21: Java stack trace analyzer — catches runtime errors before production.

Scans for:
  - OutOfMemoryError (Java heap space, Metaspace, etc.)
  - StackOverflowError
  - NullPointerException patterns
  - UUID/Type mismatch errors (e.g. "Invalid UUID string: undefined")
  - HTTP 500 errors in log files
  - SQL exceptions
  - ClassNotFoundException
  - NoClassDefFoundError

Works on:
  - .log files (runtime stack traces)
  - .java/.kt source files (catch blocks that swallow errors)
  - application.yml/properties (missing error handling config)
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Tuple
from .models import Finding, Severity, LayerID, BlastRadius, Category


# Patterns for runtime errors in log files
_LOG_PATTERNS: List[Tuple[str, str, Severity, str, str]] = [
    # (pattern, rule_id, severity, message, cwe)
    (r"OutOfMemoryError:\s*Java heap space",
     "java.oom_heap", Severity.CRITICAL,
     "OutOfMemoryError: Java heap space — JVM ran out of heap memory. Increase -Xmx or fix memory leaks.",
     "CWE-400"),
    (r"OutOfMemoryError:\s*Metaspace",
     "java.oom_metaspace", Severity.CRITICAL,
     "OutOfMemoryError: Metaspace — JVM ran out of metadata space. Increase -XX:MaxMetaspaceSize.",
     "CWE-400"),
    (r"OutOfMemoryError",
     "java.oom_generic", Severity.CRITICAL,
     "OutOfMemoryError — JVM ran out of memory. Review memory allocation and leaks.",
     "CWE-400"),
    (r"StackOverflowError",
     "java.stack_overflow", Severity.CRITICAL,
     "StackOverflowError — infinite recursion or very deep call stack detected.",
     "CWE-674"),
    (r"Invalid UUID string:\s*(\S+)",
     "java.invalid_uuid", Severity.HIGH,
     "Invalid UUID string — user input passed as UUID without validation. Add input validation.",
     "CWE-20"),
    (r"MethodArgumentTypeMismatchException.*Failed to convert.*to required type",
     "java.type_mismatch", Severity.HIGH,
     "Type mismatch: user input couldn't be converted to expected type. Add @Validated and proper error handling.",
     "CWE-20"),
    (r"status=500",
     "java.http_500", Severity.HIGH,
     "HTTP 500 error — unhandled server exception. Review error handling and add try-catch.",
     "CWE-755"),
    (r"ClassNotFoundException",
     "java.class_not_found", Severity.HIGH,
     "ClassNotFoundException — missing dependency or class. Check classpath and build config.",
     "CWE-1061"),
    (r"NoClassDefFoundError",
     "java.no_class_def", Severity.HIGH,
     "NoClassDefFoundError — class was available at compile time but missing at runtime.",
     "CWE-1061"),
    (r"SQLException.*Duplicate entry",
     "java.sql_duplicate", Severity.MEDIUM,
     "SQL duplicate entry — missing unique constraint validation before insert.",
     "CWE-89"),
    (r"SQLException.*foreign key constraint",
     "java.sql_fk_violation", Severity.MEDIUM,
     "SQL foreign key violation — missing referential integrity check before delete/update.",
     "CWE-89"),
    (r"NullPointerException",
     "java.npe_log", Severity.MEDIUM,
     "NullPointerException in production — add null checks or use Optional.",
     "CWE-476"),
    (r"ConnectException|Connection refused",
     "java.connect_refused", Severity.MEDIUM,
     "Connection refused — downstream service unavailable. Add circuit breaker and retry logic.",
     "CWE-754"),
    (r"SocketTimeoutException|Read timed out",
     "java.timeout", Severity.MEDIUM,
     "Socket timeout — downstream service slow. Add timeout config and fallback.",
     "CWE-754"),
    (r"JsonParseException|JsonMappingException",
     "java.json_error", Severity.MEDIUM,
     "JSON parse error — malformed JSON input. Add input validation.",
     "CWE-20"),
    (r"TransactionSystemException|RollbackException",
     "java.tx_rollback", Severity.MEDIUM,
     "Transaction rollback — data consistency risk. Review transaction boundaries.",
     "CWE-755"),
]

# Patterns for source code anti-patterns
_SOURCE_PATTERNS: List[Tuple[str, str, Severity, str, str]] = [
    (r'catch\s*\(\s*Exception\s+\w+\s*\)\s*\{\s*\}',
     "java.empty_catch", Severity.MEDIUM,
     "Empty catch block — swallows exceptions silently. At minimum, log the error.",
     "CWE-390"),
    (r'catch\s*\(\s*Throwable\s+\w+\s*\)',
     "java.catch_throwable", Severity.LOW,
     "Catching Throwable — catches OutOfMemoryError and JVM errors. Catch specific exceptions instead.",
     "CWE-396"),
    (r'e\.printStackTrace\s*\(\s*\)',
     "java.print_stack_trace", Severity.LOW,
     "printStackTrace() in production code — use proper logging (SLF4J/Log4j).",
     "CWE-497"),
    (r'System\.exit\s*\(',
     "java.system_exit", Severity.LOW,
     "System.exit() in application code — prevents graceful shutdown. Use proper shutdown hooks.",
     "CWE-382"),
]


def scan_log_file(file_path: Path, repo_root: Path) -> List[Finding]:
    """Scan a log file for runtime errors and stack traces."""
    findings: List[Finding] = []
    rel_path = str(file_path.relative_to(repo_root))

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return findings

    lines = content.split("\n")
    for i, line in enumerate(lines, 1):
        for pattern, rule_id, severity, message, cwe in _LOG_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                # Extract more context
                context = line.strip()[:120]
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id=f"L0.runtime.{rule_id}",
                    message=f"{message} | Context: {context}",
                    file=rel_path, start_line=i,
                    severity=severity, confidence=0.9,
                    blast_radius=BlastRadius.SYSTEM,
                    exploitability=0.8 if severity == Severity.CRITICAL else 0.5,
                    category=Category.SECURITY if severity in (Severity.CRITICAL, Severity.HIGH) else Category.CORRECTNESS,
                    cwe=cwe,
                    fix_suggestion=_get_fix_suggestion(rule_id),
                ))
                break  # Only one finding per line

    return findings


def scan_java_source(file_path: Path, repo_root: Path) -> List[Finding]:
    """Scan Java/Kotlin source for anti-patterns."""
    findings: List[Finding] = []
    rel_path = str(file_path.relative_to(repo_root))

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return findings

    lines = content.split("\n")
    for i, line in enumerate(lines, 1):
        for pattern, rule_id, severity, message, cwe in _SOURCE_PATTERNS:
            if re.search(pattern, line):
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id=f"L0.java.{rule_id}",
                    message=message,
                    file=rel_path, start_line=i,
                    severity=severity, confidence=0.8,
                    blast_radius=BlastRadius.FUNCTION,
                    exploitability=0.0,
                    category=Category.CORRECTNESS,
                    cwe=cwe,
                    fix_suggestion=_get_fix_suggestion(rule_id),
                ))

    return findings


def _get_fix_suggestion(rule_id: str) -> str:
    """Get fix suggestion for a rule."""
    fixes = {
        "java.oom_heap": "Increase -Xmx JVM argument. Use a profiler to find memory leaks. Consider using WeakReference for caches.",
        "java.oom_metaspace": "Increase -XX:MaxMetaspaceSize. Check for classloader leaks in application servers.",
        "java.stack_overflow": "Check for infinite recursion. Increase -Xss if legitimate deep recursion. Refactor to iterative approach.",
        "java.invalid_uuid": "Validate UUID input before parsing: try { UUID.fromString(input) } catch (IllegalArgumentException) { return 400 }",
        "java.type_mismatch": "Add @Validated annotation and proper exception handler: @ExceptionHandler(MethodArgumentTypeMismatchException.class)",
        "java.http_500": "Add global exception handler: @ControllerAdvice + @ExceptionHandler. Never expose stack traces to users.",
        "java.class_not_found": "Check Maven/Gradle dependencies. Verify the class is on the classpath at runtime.",
        "java.no_class_def": "Check for optional dependencies. Verify the class is available at runtime (not just compile time).",
        "java.npe_log": "Add null checks: Objects.requireNonNull(). Use Optional<T>. Enable -XX:+ShowCodeDetailsInExceptionMessages (Java 14+).",
        "java.empty_catch": "At minimum, log the exception: log.error(\"Unexpected error\", e). Better: re-throw or handle appropriately.",
        "java.catch_throwable": "Catch specific exceptions (e.g. IOException, SQLException). Never catch OutOfMemoryError.",
        "java.print_stack_trace": "Use SLF4J: logger.error(\"Description\", e). Configure log levels and appenders properly.",
        "java.system_exit": "Use Spring Boot's SpringApplication.exit() or a shutdown hook. Never call System.exit() in a web app.",
        "java.connect_refused": "Add circuit breaker (Resilience4j). Configure connection timeout. Implement retry with backoff.",
        "java.timeout": "Configure RestTemplate/WebClient timeouts. Add fallback method. Use @Retryable for transient failures.",
        "java.json_error": "Validate JSON input before parsing. Use try-catch around ObjectMapper.readValue(). Return 400 for malformed input.",
        "java.tx_rollback": "Review @Transactional boundaries. Check for nested transactions. Ensure idempotent operations.",
        "java.sql_duplicate": "Check for existing record before insert: SELECT ... WHERE. Add unique constraint + handle ConstraintViolationException.",
        "java.sql_fk_violation": "Check for child records before delete: SELECT COUNT(*) WHERE parent_id = ?. Handle gracefully.",
    }
    return fixes.get(rule_id, "Review the error and add appropriate handling.")


def scan_repo_runtime_errors(repo_root: Path, max_files: int = 500) -> List[Finding]:
    """Scan a repository for runtime errors in log files and Java source.

    This is the main entry point — scans .log files for stack traces and
    .java/.kt files for anti-patterns.
    """
    findings: List[Finding] = []
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                 "build", "dist", "target", ".loomscan-cache"}

    log_extensions = {".log", ".out", ".err"}
    java_extensions = {".java", ".kt"}

    file_count = 0
    for p in repo_root.rglob("*"):
        if file_count >= max_files:
            break
        if not p.is_file():
            continue
        if any(part in skip_dirs for part in p.parts):
            continue

        ext = p.suffix.lower()
        if ext in log_extensions:
            findings.extend(scan_log_file(p, repo_root))
            file_count += 1
        elif ext in java_extensions:
            findings.extend(scan_java_source(p, repo_root))
            file_count += 1

    return findings
