"""v6.0: Domain-aware business logic spec mining.

Catches business logic bugs that generic spec mining misses:
  - Negative quantity/amount (e.g., order with qty=-5 gives refund)
  - Missing price validation (price=0 or price=-1)
  - Missing balance check before withdrawal
  - Missing inventory check before order
  - Unbounded loop on user-controlled counter

Unlike generic spec mining (which mines API usage patterns), this module
understands DOMAIN CONCEPTS: quantity, price, amount, balance, inventory,
discount, tax. It mines the codebase for validation patterns on these
fields and flags functions where validation is missing.

How it works:
  1. Scans all Python/Java/JS files for domain-variable patterns:
     `if qty > 0`, `if amount >= 0`, `if price > 0`, `if balance >= amount`
  2. Builds a "validation profile" — which domain variables are validated
     and how (positive check, range check, comparison check).
  3. For each function that uses a domain variable WITHOUT validation,
     flags it as a business logic risk.
"""
from __future__ import annotations

import re
import ast
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional
from .models import Finding, Severity, LayerID, BlastRadius, Category


# Domain variable name patterns (case-insensitive)
_DOMAIN_VARS = {
    "quantity": ["qty", "quantity", "count", "num", "number", "amount", "volume", "size"],
    "price": ["price", "cost", "rate", "fee", "charge", "amount_due", "subtotal", "total"],
    "money": ["balance", "amount", "deposit", "withdrawal", "transfer", "payment", "refund",
              "credit", "debit", "salary", "wage", "bonus", "commission"],
    "inventory": ["stock", "inventory", "available", "on_hand", "quantity_available"],
    "discount": ["discount", "rebate", "coupon", "promo", "markdown", "reduction"],
    "tax": ["tax", "vat", "gst", "sales_tax", "tax_rate"],
    "user_input_numeric": ["score", "rating", "points", "level", "rank", "priority"],
}

# Validation patterns (what "good" validation looks like)
_VALIDATION_PATTERNS = {
    "positive_check": r'if\s+\w*(qty|quantity|amount|price|count|total|score|volume)\w*\s*(?:>|>=|==)\s*[1-9]',
    "non_negative_check": r'if\s+\w*(qty|quantity|amount|price|count|total|balance|deposit)\w*\s*(?:>=|>|==)\s*0',
    "balance_check": r'if\s+\w*balance\w*\s*(?:>=|>)\s*\w*(amount|withdrawal|transfer|payment)\w*',
    "range_check": r'if\s+\w*(qty|quantity|amount|price|count|score|rating)\w*\s*(?:<|<=|>=|>)\s*\d+',
    "is_positive": r'\w*(qty|quantity|amount|price)\w*\s*(?:>|>=)\s*[1-9]',
}

# Risk patterns (what "bad" code looks like — domain var used without validation)
_RISK_PATTERNS: List[Tuple[str, str, Severity, str, str]] = [
    # Negative quantity in arithmetic
    (r'\b(qty|quantity|count|amount)\b\s*[\*]\s*\w*(price|cost|rate)\b',
     "bl.negative_quantity_arithmetic",
     Severity.HIGH,
     "Business logic: qty * price without validation — negative qty gives negative total (refund). Validate qty > 0 before multiplication.",
     "CWE-840"),
    # Negative amount in DB write
    (r'\b(refund|credit|withdrawal|transfer)\b.*\bamount\b',
     "bl.negative_amount_operation",
     Severity.HIGH,
     "Business logic: financial operation with amount — verify amount is non-negative. Negative amount could reverse the transaction direction.",
     "CWE-840"),
    # Balance check missing before withdrawal
    (r'(withdraw|transfer|deduct|subtract)\w*\s*\([^)]*amount',
     "bl.missing_balance_check",
     Severity.HIGH,
     "Business logic: withdrawal/transfer without visible balance check — may allow overdraft. Verify balance >= amount before deducting.",
     "CWE-840"),
    # Price set from user input without validation
    (r'\bprice\s*=\s*(?:request|req|input|body|params|form|data)\b',
     "bl.price_from_user_input",
     Severity.CRITICAL,
     "Business logic: price assigned from user input — attacker can set price=0 or negative. Validate price > 0 server-side.",
     "CWE-840"),
    # Discount > 100% or negative
    (r'\bdiscount\s*=\s*(?:request|req|input|body|params|form|data)\b',
     "bl.discount_from_user_input",
     Severity.HIGH,
     "Business logic: discount from user input — verify 0 <= discount <= 100. Negative discount increases price; >100 gives money back.",
     "CWE-840"),
    # Tax rate from user input
    (r'\btax(?:_rate)?\s*=\s*(?:request|req|input|body|params|form|data)\b',
     "bl.tax_from_user_input",
     Severity.HIGH,
     "Business logic: tax rate from user input — verify 0 <= tax_rate <= 1.0. Negative or >1 tax is invalid.",
     "CWE-840"),
    # Score/rating from user input without range check
    (r'\b(score|rating)\s*=\s*(?:request|req|input|body|params|form|data)\b',
     "bl.score_from_user_input",
     Severity.MEDIUM,
     "Business logic: score/rating from user input — validate range (e.g., 0-5, 0-100). Without validation, attacker can set arbitrary scores.",
     "CWE-840"),
    # Quantity update without check
    (r'(update|set|save|insert)\w*.*\b(qty|quantity|stock|inventory)\b',
     "bl.quantity_update_no_check",
     Severity.MEDIUM,
     "Business logic: quantity/stock update — verify new value is non-negative. Negative stock is invalid.",
     "CWE-840"),
]


# =============================================================================
# v7.3: DB domain-aware patterns — catches architectural DB anti-patterns that
# regex rules alone cannot express. These need cross-line context (load + use).
# =============================================================================
_DB_RISK_PATTERNS: List[Tuple[str, str, Severity, str, str]] = [
    # --- Unnecessary load ---
    # Loading entire table just to get .size()
    (r'\b\w+\s*=\s*\w+\.findAll\s*\(\s*\)\s*;\s*\n\s*[^;]*\.size\s*\(\s*\)',
     "bl.db.load_all_for_count",
     Severity.HIGH,
     "Business logic: Loaded entire table into memory just to call .size() — issues a full SELECT + entity hydration. Use repository.count() for a single SQL COUNT(*) query.",
     "CWE-400"),
    # Loading entity just to access one field (Java pattern: User u = repo.findById(id).orElse(null); ... u.getEmail())
    (r'\b\w+\s+\w+\s*=\s*\w+\.(?:findById|findByName|findOne)\s*\([^)]*\)(?:\.orElse[^;]*)?;\s*\n?\s*[^;]*\b\.get\w+\s*\(\s*\)',
     "bl.db.load_entity_for_one_field",
     Severity.MEDIUM,
     "Business logic: Loaded full entity just to access one field — fetches all columns. Use a JPQL projection (SELECT u.email FROM User u) or a DTO constructor expression.",
     "CWE-400"),
    # Loading all records then filtering in Java
    (r'\bList\s*<\s*\w+\s*>\s+\w+\s*=\s*\w+\.findAll\s*\(\s*\)\s*;\s*\n\s*for\s*\(',
     "bl.db.load_all_then_filter",
     Severity.HIGH,
     "Business logic: Loaded all records into memory then filtered in a Java loop — O(N) memory + DB I/O. Add a WHERE clause to the @Query / use findBy<Property>(...) derived query.",
     "CWE-400"),
    # Loading list then iterating to find one item (chained call form)
    (r'\w+\.findAll\s*\(\s*\)\s*\.\s*stream\s*\(\s*\)\s*\.\s*filter\s*\(',
     "bl.db.load_all_then_stream_filter",
     Severity.HIGH,
     "Business logic: Loaded all records then used stream().filter() to find one — full table scan + in-memory filter. Push the predicate into the database query.",
     "CWE-400"),
    # findAll inside contains() check
    (r'\w+\.findAll\s*\(\s*\)\s*\.\s*contains\s*\(',
     "bl.db.load_all_for_contains",
     Severity.HIGH,
     "Business logic: findAll().contains(x) — loads every row into memory to check membership. Use repository.existsBy<Property>(...) which compiles to SELECT 1 ... LIMIT 1.",
     "CWE-400"),
    # findAll inside equals() check on a field
    (r'\w+\.findAll\s*\(\s*\)\s*\.\s*stream\s*\(\s*\)\s*\.\s*anyMatch\s*\(',
     "bl.db.load_all_for_anymatch",
     Severity.HIGH,
     "Business logic: findAll().stream().anyMatch(...) — loads all rows to check existence. Use repository.existsBy<Property>(...) — single indexed SELECT.",
     "CWE-400"),

    # --- Unnecessary write ---
    # Saving entity without modifying it (heuristic: load then save with no setter in between)
    (r'\b\w+\s+\w+\s*=\s*\w+\.findById\s*\([^)]*\)\s*(?:\.orElse\s*\([^)]*\)\s*)?;\s*\n?\s*\w+\.save\s*\(\s*\w+\s*\)',
     "bl.db.save_unchanged",
     Severity.MEDIUM,
     "Business logic: Entity loaded then saved without any visible modification — wasted DB write (UPDATE no-op). Only call save() after modifying fields; or use dirty-checking (managed entity auto-flushes).",
     "CWE-400"),
    # Delete followed by insert of same entity type (drop the backreference — entity
    # type may differ between variable name and `new Type` constructor call)
    (r'\.delete\s*\(\s*\w+\s*\)\s*;\s*\n?\s*\w+\.save\s*\(\s*new\s+\w+',
     "bl.db.delete_then_insert",
     Severity.MEDIUM,
     "Business logic: delete() followed by save(new ...) of same entity — 2 queries (DELETE+INSERT) instead of 1 UPDATE. Use EntityManager.merge() or update fields in place.",
     "CWE-400"),
    # Saving inside if-exists check (should be UPSERT)
    (r'if\s*\(\s*!\w+\.existsBy\w+\s*\([^)]*\)\s*\)\s*\{[^}]*\.save\s*\(',
     "bl.db.exists_then_save",
     Severity.LOW,
     "Business logic: if-not-exists then save — TOCTOU race under concurrent load (two threads pass the check, both insert). Use a DB UNIQUE constraint + catch DataIntegrityViolationException.",
     "CWE-362"),

    # --- Wasted DB round-trips ---
    # existsById + findById in same function (allow across multiple lines incl. if-block braces)
    (r'\.existsById\s*\(\s*\w+\s*\)[^;]*\)\s*\{?\s*\n?\s*[^;]*\.findById\s*\(\s*\w+\s*\)',
     "bl.db.exists_then_find",
     Severity.MEDIUM,
     "Business logic: existsById() followed by findById() — 2 DB round-trips for the same check. Just call findById().orElseThrow(...) — 1 query.",
     "CWE-400"),
    # count() then findAll() (e.g., to short-circuit empty)
    (r'count\s*\(\s*\)[^;]*;\s*\n?\s*if\s*\([^)]+\)\s*\{?\s*\n?\s*[^;]*\.findAll\s*\(',
     "bl.db.count_then_findall",
     Severity.MEDIUM,
     "Business logic: count() then findAll() — 2 DB queries. Use findAll().isEmpty() (1 query) or wrap the check in a single EXISTS query.",
     "CWE-400"),

    # --- Cache misuse in business logic ---
    # Repeated DB query inside a method without @Cacheable
    (r'public\s+\w+\s+get\w+\s*\([^)]*\)\s*\{[^}]*repository\.find\w+\s*\(',
     "bl.db.uncached_lookup",
     Severity.LOW,
     "Business logic: get...() method calls repository.find...() on every invocation — if the underlying data rarely changes, add @Cacheable to avoid repeated DB load. Pair with @CacheEvict on writes.",
     "CWE-400"),

    # --- Read-modify-write without locking ---
    # findById then modify then save, without @Lock / @Version
    (r'\.findById\s*\([^)]*\)\s*(?:\.orElse[^;]*)?;\s*\n?\s*[^;]*\.set\w+\s*\([^)]*\)\s*;\s*\n?\s*[^;]*\.save\s*\(',
     "bl.db.read_modify_write_no_lock",
     Severity.HIGH,
     "Business logic: read-modify-write cycle without optimistic/pessimistic lock — lost update under concurrent transactions. Add @Version for optimistic locking, or use SELECT ... FOR UPDATE.",
     "CWE-362"),

    # --- Pagination missing on user-facing list endpoints ---
    # Controller returns List<...> without Pageable parameter
    (r'@(?:Get|Post)Mapping\s*\([^)]*\)\s*\n?\s*public\s+(?:List|Set)\s*<\s*\w+\s*>\s+\w+\s*\(\s*\)(?![^\n]*(?:Pageable|@Cacheable))',
     "bl.db.unpaginated_endpoint",
     Severity.HIGH,
     "Business logic: endpoint returns List<T> with no Pageable parameter — unbounded result set. As the table grows, this returns thousands of rows per request → OOM and slow responses. Accept Pageable and return Page<T>.",
     "CWE-400"),

    # --- N+1 in iteration ---
    # Accessing @ManyToOne / collection inside a for loop
    (r'for\s*\(\s*\w+\s+\w+\s*:\s*\w+\s*\)\s*\{[^}]*\b\w+\.(?:get|find)\w+\s*\(',
     "bl.db.n_plus_1_in_loop",
     Severity.HIGH,
     "Business logic: DB call inside a for-loop over a list — classic N+1 (1 query for the list, N for the inner lookups). Use JOIN FETCH in the @Query or batch-load via findAllById() before the loop.",
     "CWE-400"),

    # --- Pagination misuse ---
    # findAll(PageRequest.of(0, MAX_VALUE)) — defeats pagination
    (r'PageRequest\.of\s*\(\s*\d+\s*,\s*(?:Integer\.MAX_VALUE|99999|100000|1000000)\b',
     "bl.db.page_size_too_large",
     Severity.HIGH,
     "Business logic: PageRequest with extremely large page size — effectively unbounded. Cap page size at server config (e.g., max 100) and reject oversized requests.",
     "CWE-400"),

    # --- Logging sensitive DB data ---
    # log.info(repository.findById(...)) — logs the full entity
    (r'log(?:ger)?\.(?:info|debug|warn)\s*\(\s*[^)]*repository\.(?:findById|findAll|find)',
     "bl.db.log_entity",
     Severity.MEDIUM,
     "Business logic: logging the result of a repository.find...() call — may serialize PII/secrets to logs. Log only the entity ID, or sanitize fields before logging.",
     "CWE-532"),
]


# =============================================================================
# v7.3.1: Java/Spring-specific cross-line patterns — common production errors
# that need function-level context to detect.
# =============================================================================
_JAVA_RISK_PATTERNS: List[Tuple[str, str, Severity, str, str]] = [
    # parallelStream() inside a request handler — steals from common ForkJoinPool
    (r'@(?:Get|Post|Put|Patch|Delete)Mapping\s*\([^)]*\)\s*\n?\s*public\s+\w+\s+\w+\s*\([^)]*\)\s*\{[^}]*\.parallelStream\s*\(\s*\)',
     "bl.java.parallel_stream_in_request",
     Severity.HIGH,
     "Business logic: parallelStream() in a request handler — uses the shared ForkJoinPool.commonPool(). Under concurrent load, all requests compete for the same pool → thread starvation and 5xx errors. Use a dedicated executor.",
     "CWE-400"),

    # Collectors.toMap with potential duplicate key — throws IllegalStateException
    (r'\.collect\s*\(\s*Collectors\.toMap\s*\(\s*[^,]+,\s*[^,]+(?![^)]*\(\s*\w+\s*,\s*\([^)]*\)\s*->)[^)]*\)\s*\)',
     "bl.java.collectors_tomap_no_merge",
     Severity.MEDIUM,
     "Business logic: Collectors.toMap without a merge function — throws IllegalStateException('Duplicate key') if two stream elements map to the same key. Add a third arg: `(a, b) -> a` or `(a, b) -> b`.",
     "CWE-755"),

    # Stream consumed twice (terminal op called on same stream variable)
    (r'(\w+)\s*=\s*\w+\.stream\s*\(\s*\)(?:[^;]*;[^;]*)?\1\.(?:count|collect|toList|findFirst|forEach|reduce)\s*\(',
     "bl.java.stream_consumed_twice",
     Severity.HIGH,
     "Business logic: Stream variable used after a terminal op — throws IllegalStateException('stream has already been operated upon or closed'). Streams are single-use; create a new one or collect to a List first.",
     "CWE-755"),

    # Optional chain ending in .get() (no isPresent check)
    (r'\.stream\s*\(\s*\)\s*\.\s*filter\s*\([^)]*\)\s*\.\s*findFirst\s*\(\s*\)\s*\.\s*get\s*\(\s*\)',
     "bl.java.optional_chain_get",
     Severity.HIGH,
     "Business logic: stream().filter().findFirst().get() — throws NoSuchElementException if no element matches. Use .orElse(default) or .orElseThrow(() -> new NotFoundException()).",
     "CWE-476"),

    # try { ... } catch (Exception e) { return null; } — swallows exception
    (r'try\s*\{[^}]{0,200}\}\s*catch\s*\(\s*Exception\s+\w+\s*\)\s*\{\s*return\s+null\s*;\s*\}',
     "bl.java.swallow_exception_return_null",
     Severity.HIGH,
     "Business logic: catch (Exception e) { return null; } — swallows ALL exceptions and returns null. Caller can't distinguish 'not found' from 'DB error' from 'NPE'. Throw a domain exception or return Optional.empty().",
     "CWE-390"),

    # Catch + log.error + rethrow same exception — double-logs and loses stack
    (r'catch\s*\(\s*(\w+)\s+(\w+)\s*\)\s*\{\s*log(?:ger)?\.error\s*\([^)]*,\s*\2\s*\)\s*;\s*throw\s+\2\s*;',
     "bl.java.catch_log_rethrow",
     Severity.LOW,
     "Business logic: catch + log + rethrow same exception — logs it twice (here and at the outer handler) and the rethrow loses the original stack frame. Either log OR rethrow, not both. If you must, wrap: `throw new DomainException(\"msg\", e)`.",
     "CWE-778"),

    # Synchronous HTTP call inside a request handler (no async, no timeout)
    (r'@(?:Get|Post|Put|Patch|Delete)Mapping\s*\([^)]*\)\s*\n?\s*public\s+\w+\s+\w+\s*\([^)]*\)\s*\{[^}]*(?:restTemplate|RestTemplate|webClient|WebClient|HttpClient)\.',
     "bl.java.sync_http_in_request",
     Severity.MEDIUM,
     "Business logic: synchronous HTTP call inside a request handler — adds downstream latency to user response. If the downstream service is slow (57s), the user request times out too. Use WebClient (async) or @Async + CompletableFuture.",
     "CWE-400"),

    # Loop that calls .size() on a collection that grows inside the loop
    (r'for\s*\(\s*(?:int|Integer)\s+\w+\s*=\s*0\s*;\s*\w+\s*<\s*\w+\.size\s*\(\s*\)\s*;\s*\w+\+\+\s*\)\s*\{[^}]*\.add\s*\(',
     "bl.java.loop_size_grows",
     Severity.HIGH,
     "Business logic: for loop bounded by collection.size() while calling .add() inside — infinite loop or way more iterations than expected. Cache the size before the loop: `int n = list.size(); for (int i = 0; i < n; i++)`.",
     "CWE-835"),

    # Stream.forEach with side-effect on shared state (mutating external collection)
    (r'\.stream\s*\(\s*\)\s*\.\s*forEach\s*\(\s*\w+\s*->\s*\w+\.add\s*\(',
     "bl.java.stream_for_each_side_effect",
     Severity.MEDIUM,
     "Business logic: stream().forEach(...) mutating external collection — not thread-safe if the stream is parallel. Use `.collect(Collectors.toList())` for accumulation, or `.forEachOrdered()` if mutation is required.",
     "CWE-362"),

    # @Transactional private method — Spring AOP proxy won't intercept
    (r'@Transactional\s*\n?\s*private\s+\w+\s+\w+\s*\(',
     "bl.java.transactional_private_method",
     Severity.HIGH,
     "Business logic: @Transactional on a private method — Spring's AOP proxy cannot intercept private methods, so the transaction is silently NOT applied. Make the method public, or use AspectJ weaving, or move the @Transactional to a public wrapper.",
     "CWE-755"),

    # @Transactional method called from same class (self-invocation) — proxy bypassed
    (r'public\s+\w+\s+(\w+)\s*\([^)]*\)\s*\{[^}]*this\.\1\s*\(',
     "bl.java.transactional_self_invocation",
     Severity.MEDIUM,
     "Business logic: this.sameMethod() — Spring @Transactional is bypassed on self-invocation (proxy doesn't intercept internal calls). Inject the bean as a field and call bean.method(), or use AopContext.currentProxy().",
     "CWE-755"),

    # Catching InterruptedException without restoring interrupt flag
    (r'catch\s*\(\s*InterruptedException\s+\w+\s*\)\s*\{[^}]*(?!Thread\.currentThread\(\)\.interrupt)[^}]*\}',
     "bl.java.interrupted_not_restored",
     Severity.MEDIUM,
     "Business logic: InterruptedException caught but Thread.currentThread().interrupt() not called — cooperative cancellation broken, thread pool can't shut down cleanly. Always restore the interrupt flag in the catch block.",
     "CWE-755"),

    # Collectors.toList() then .size() == 0 instead of .isEmpty()
    (r'\.collect\s*\(\s*Collectors\.toList\s*\(\s*\)\s*\)\s*\.\s*size\s*\(\s*\)\s*==\s*0',
     "bl.java.collect_size_zero",
     Severity.LOW,
     "Business logic: .collect(toList()).size() == 0 — uses 2 ops + allocates a List. Use `.collect(Collectors.toList()).isEmpty()` or better `.findAny().isPresent()` (short-circuits).",
     "CWE-400"),

    # Multiple sequential findById calls that could be batched
    (r'\.findById\s*\(\s*\w+\s*\)(?:\.orElse[^;]*)?;\s*\n?\s*[^;]*\.findById\s*\(\s*\w+\s*\)(?:\.orElse[^;]*)?;\s*\n?\s*[^;]*\.findById\s*\(\s*\w+\s*\)',
     "bl.java.multiple_findbyid",
     Severity.MEDIUM,
     "Business logic: 3+ sequential findById() calls — 3 DB round-trips. Use findAllById(List.of(id1, id2, id3)) for a single SELECT ... WHERE id IN (...) query.",
     "CWE-400"),

    # Stream.count() then comparing to 0 — should use findAny().isPresent()
    (r'\.stream\s*\(\s*\)\s*\.\s*filter\s*\([^)]*\)\s*\.\s*count\s*\(\s*\)\s*(?:==|>)\s*0',
     "bl.java.stream_count_zero",
     Severity.LOW,
     "Business logic: stream().filter().count() == 0 — iterates the entire stream just to check emptiness. Use .findAny().isPresent() or .noneMatch(...) — short-circuits on first match.",
     "CWE-400"),

    # Stream.collect then iterate — could have used forEach directly
    (r'\.stream\s*\(\s*\)\s*\.\s*filter\s*\([^)]*\)\s*\.\s*collect\s*\(\s*Collectors\.toList\s*\(\s*\)\s*\)\s*\.\s*forEach\s*\(',
     "bl.java.collect_then_foreach",
     Severity.LOW,
     "Business logic: .collect(toList()).forEach(...) — allocates an intermediate List unnecessarily. Use .forEach(...) directly on the stream (unless you need the list for other purposes).",
     "CWE-400"),
]


# DB-specific validation patterns that suppress a finding if present nearby
_DB_VALIDATION_PATTERNS = {
    "lock": r'@Version|@Lock|FOR\s+UPDATE|LockModeType\.(?:OPTIMISTIC|PESSIMISTIC)',
    "cache": r'@Cacheable|@Cache\b',
    "pagination": r'Pageable|PageRequest\.of\s*\(\s*\d+\s*,\s*\d{1,3}\b',
    "batch": r'saveAll|batchUpdate|addBatch|persist\s*\([^)]*\)\s*;[^;]*persist',
    "projection": r'SELECT\s+new\s+\w+|@Query\s*\([^)]*SELECT\s+\w+\.',
}


def scan_python_business_logic(file_path: Path, repo_root: Path) -> List[Finding]:
    """Scan a Python file for business logic bugs using AST + heuristics."""
    if file_path.suffix != '.py':
        return []
    try:
        source = file_path.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return []

    rel_path = str(file_path.relative_to(repo_root))
    findings: List[Finding] = []

    # Parse AST to find functions and their validation patterns
    try:
        tree = ast.parse(source)
    except Exception:
        return []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        func_source = ast.get_source_segment(source, node) or ""
        func_name = node.name

        # Skip __init__, __str__, etc.
        if func_name.startswith('_') and func_name != '__init__':
            continue

        # Check each risk pattern against the function source
        for pattern, rule_id, severity, message, cwe in _RISK_PATTERNS:
            if re.search(pattern, func_source, re.IGNORECASE):
                # Check if the function has validation for this domain variable
                has_validation = any(
                    re.search(vp, func_source, re.IGNORECASE)
                    for vp in _VALIDATION_PATTERNS.values()
                )
                if not has_validation:
                    findings.append(Finding(
                        layer=LayerID.L0_FAST,
                        rule_id=f"L0.{rule_id}",
                        message=f"{message} | Function: {func_name}()",
                        file=rel_path, start_line=node.lineno,
                        severity=severity, confidence=0.7,
                        blast_radius=BlastRadius.MODULE,
                        exploitability=0.8,
                        category=Category.CORRECTNESS,
                        cwe=cwe,
                        fix_suggestion=_get_bl_fix(rule_id),
                    ))

        # v7.3: DB domain patterns (function-scoped — they're inherently cross-line,
        # so func_source is the natural unit of analysis)
        for pattern, rule_id, severity, message, cwe in _DB_RISK_PATTERNS:
            for m in re.finditer(pattern, func_source, re.IGNORECASE | re.MULTILINE):
                suppressed = False
                if rule_id == "bl.db.read_modify_write_no_lock":
                    if re.search(_DB_VALIDATION_PATTERNS["lock"], func_source, re.IGNORECASE):
                        suppressed = True
                elif rule_id == "bl.db.uncached_lookup":
                    if re.search(_DB_VALIDATION_PATTERNS["cache"], func_source, re.IGNORECASE):
                        suppressed = True
                elif rule_id == "bl.db.unpaginated_endpoint":
                    if re.search(_DB_VALIDATION_PATTERNS["pagination"], func_source, re.IGNORECASE):
                        suppressed = True
                elif rule_id == "bl.db.load_entity_for_one_field":
                    if re.search(_DB_VALIDATION_PATTERNS["projection"], func_source, re.IGNORECASE):
                        suppressed = True
                elif rule_id == "bl.db.n_plus_1_in_loop":
                    if re.search(r'findAllById|saveAll|JOIN\s+FETCH|@EntityGraph', func_source, re.IGNORECASE):
                        suppressed = True
                if suppressed:
                    continue
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id=f"L0.{rule_id}",
                    message=f"{message} | Function: {func_name}()",
                    file=rel_path, start_line=node.lineno,
                    severity=severity, confidence=0.7,
                    blast_radius=BlastRadius.MODULE,
                    exploitability=0.6,
                    category=Category.CORRECTNESS,
                    cwe=cwe,
                    fix_suggestion=_get_db_bl_fix(rule_id),
                ))

        # v7.3.1: Java/Spring-specific cross-line patterns
        for pattern, rule_id, severity, message, cwe in _JAVA_RISK_PATTERNS:
            for m in re.finditer(pattern, func_source, re.IGNORECASE | re.MULTILINE):
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id=f"L0.{rule_id}",
                    message=f"{message} | Function: {func_name}()",
                    file=rel_path, start_line=node.lineno,
                    severity=severity, confidence=0.7,
                    blast_radius=BlastRadius.MODULE,
                    exploitability=0.6,
                    category=Category.CORRECTNESS,
                    cwe=cwe,
                    fix_suggestion=_get_java_bl_fix(rule_id),
                ))

    return findings


def scan_java_business_logic(file_path: Path, repo_root: Path) -> List[Finding]:
    """Scan a Java file for business logic bugs using regex."""
    return _scan_regex_business_logic(file_path, repo_root)


def scan_js_business_logic(file_path: Path, repo_root: Path) -> List[Finding]:
    """Scan a JavaScript file for business logic bugs using regex."""
    return _scan_regex_business_logic(file_path, repo_root)


def _scan_regex_business_logic(file_path: Path, repo_root: Path) -> List[Finding]:
    """Scan a file using regex for business logic risks (incl. v7.3 DB patterns)."""
    try:
        content = file_path.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return []

    rel_path = str(file_path.relative_to(repo_root))
    findings: List[Finding] = []

    # Original risk patterns (domain arithmetic / pricing)
    for pattern, rule_id, severity, message, cwe in _RISK_PATTERNS:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            line_num = content[:match.start()].count('\n') + 1
            # Check if there's validation nearby (within 10 lines)
            start = max(0, match.start() - 500)
            end = min(len(content), match.end() + 500)
            context = content[start:end]
            has_validation = any(
                re.search(vp, context, re.IGNORECASE)
                for vp in _VALIDATION_PATTERNS.values()
            )
            if not has_validation:
                findings.append(Finding(
                    layer=LayerID.L0_FAST,
                    rule_id=f"L0.{rule_id}",
                    message=message,
                    file=rel_path, start_line=line_num,
                    severity=severity, confidence=0.65,
                    blast_radius=BlastRadius.MODULE,
                    exploitability=0.7,
                    category=Category.CORRECTNESS,
                    cwe=cwe,
                    fix_suggestion=_get_bl_fix(rule_id),
                ))

    # v7.3: DB domain-aware patterns (cross-line context)
    for pattern, rule_id, severity, message, cwe in _DB_RISK_PATTERNS:
        for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
            line_num = content[:match.start()].count('\n') + 1
            # Look for suppression signals within +/- 20 lines
            start = max(0, match.start() - 1500)
            end = min(len(content), match.end() + 1500)
            context = content[start:end]
            # Some patterns have specific suppression conditions
            suppressed = False
            if rule_id == "bl.db.read_modify_write_no_lock":
                if re.search(_DB_VALIDATION_PATTERNS["lock"], context, re.IGNORECASE):
                    suppressed = True
            elif rule_id == "bl.db.uncached_lookup":
                if re.search(_DB_VALIDATION_PATTERNS["cache"], context, re.IGNORECASE):
                    suppressed = True
            elif rule_id == "bl.db.unpaginated_endpoint":
                if re.search(_DB_VALIDATION_PATTERNS["pagination"], context, re.IGNORECASE):
                    suppressed = True
            elif rule_id == "bl.db.load_entity_for_one_field":
                if re.search(_DB_VALIDATION_PATTERNS["projection"], context, re.IGNORECASE):
                    suppressed = True
            elif rule_id in ("bl.db.n_plus_1_in_loop",):
                if re.search(r'findAllById|saveAll|JOIN\s+FETCH|@EntityGraph', context, re.IGNORECASE):
                    suppressed = True
            if suppressed:
                continue
            findings.append(Finding(
                layer=LayerID.L0_FAST,
                rule_id=f"L0.{rule_id}",
                message=message,
                file=rel_path, start_line=line_num,
                severity=severity, confidence=0.7,
                blast_radius=BlastRadius.MODULE,
                exploitability=0.6,
                category=Category.CORRECTNESS,
                cwe=cwe,
                fix_suggestion=_get_db_bl_fix(rule_id),
            ))

    # v7.3.1: Java/Spring-specific cross-line patterns
    for pattern, rule_id, severity, message, cwe in _JAVA_RISK_PATTERNS:
        for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
            line_num = content[:match.start()].count('\n') + 1
            findings.append(Finding(
                layer=LayerID.L0_FAST,
                rule_id=f"L0.{rule_id}",
                message=message,
                file=rel_path, start_line=line_num,
                severity=severity, confidence=0.7,
                blast_radius=BlastRadius.MODULE,
                exploitability=0.6,
                category=Category.CORRECTNESS,
                cwe=cwe,
                fix_suggestion=_get_java_bl_fix(rule_id),
            ))

    return findings


def _get_bl_fix(rule_id: str) -> str:
    fixes = {
        "bl.negative_quantity_arithmetic": "Add validation: if qty <= 0: raise ValueError('Quantity must be positive'). Or use abs(qty) if negative is impossible by design.",
        "bl.negative_amount_operation": "Add validation: if amount < 0: raise ValueError('Amount cannot be negative'). Log the attempt for fraud detection.",
        "bl.missing_balance_check": "Add balance check: if account.balance < amount: raise InsufficientFundsError(). Use SELECT FOR UPDATE to prevent concurrent withdrawal race.",
        "bl.price_from_user_input": "Never trust user-provided prices. Look up price from database using product ID. If user can set price, validate: if price <= 0: reject.",
        "bl.discount_from_user_input": "Validate discount: if discount < 0 or discount > MAX_DISCOUNT: reject. Store MAX_DISCOUNT in config, not in code.",
        "bl.tax_from_user_input": "Never accept tax rate from user input. Calculate tax server-side using the user's jurisdiction. If user-provided, validate 0 <= rate <= 1.0.",
        "bl.score_from_user_input": "Validate score range: if score < MIN_SCORE or score > MAX_SCORE: reject. Use @Min/@Max annotations in Java, or if-checks in Python/JS.",
        "bl.quantity_update_no_check": "Before update: if new_quantity < 0: raise ValueError('Quantity cannot be negative'). Use database CHECK constraint: quantity >= 0.",
    }
    return fixes.get(rule_id, "Add domain-specific validation: verify the value is within expected bounds before using it.")


def _get_db_bl_fix(rule_id: str) -> str:
    """Fix suggestions for v7.3 DB business-logic findings."""
    fixes = {
        "bl.db.load_all_for_count": "Replace `repo.findAll().size()` with `repo.count()` — single SQL COUNT(*), no entity hydration.",
        "bl.db.load_entity_for_one_field": "Use a JPQL projection: `SELECT u.email FROM User u WHERE u.id = :id`. Or a DTO constructor expression `SELECT new com.example.UserEmailDto(u.email) FROM User u`.",
        "bl.db.load_all_then_filter": "Push the predicate into the DB: `repo.findByStatus(status)` (derived query) or `@Query(\"SELECT u FROM User u WHERE u.status = :status\")`.",
        "bl.db.load_all_then_stream_filter": "Replace `findAll().stream().filter(...)` with a derived query like `findByName(name)` or a JPQL `WHERE` clause.",
        "bl.db.load_all_for_contains": "Replace `findAll().contains(x)` with `existsByProperty(...)` — compiles to `SELECT 1 ... LIMIT 1`.",
        "bl.db.load_all_for_anymatch": "Replace `findAll().stream().anyMatch(...)` with `existsByProperty(...)` — single indexed SELECT.",
        "bl.db.save_unchanged": "Either remove the save() call (managed entities auto-flush on tx commit), or only call save() after modifying fields. Consider dirty-checking semantics.",
        "bl.db.delete_then_insert": "Use `repo.save(existingEntity)` after modifying fields in place — Hibernate issues a single UPDATE. Or use `EntityManager.merge(detached)`.",
        "bl.db.exists_then_save": "Add a UNIQUE constraint on the natural key and catch `DataIntegrityViolationException`. Avoids TOCTOU race under concurrent inserts.",
        "bl.db.exists_then_find": "Replace `if (existsById(id)) findById(id)` with `findById(id).orElseThrow(() -> new NotFoundException(id))` — 1 query instead of 2.",
        "bl.db.count_then_findall": "Replace `if (count() > 0) findAll()` with `findAll().isEmpty()` (single query) or use a derived `existsBy...` query.",
        "bl.db.uncached_lookup": "Add `@Cacheable(\"lookupCache\")` to the getter and `@CacheEvict` on writes. Configure a TTL in cache config.",
        "bl.db.read_modify_write_no_lock": "Add `@Version` (optimistic lock) on the entity, or use `@Lock(LockModeType.PESSIMISTIC_WRITE)` on the repository method. Catch `OptimisticLockException` and retry.",
        "bl.db.unpaginated_endpoint": "Change signature to `Page<Entity> list(Pageable pageable)` and accept `?page=0&size=20` from the client. Cap `size` at server config (e.g., max 100).",
        "bl.db.n_plus_1_in_loop": "Pre-load related entities with `findAllById(ids)` before the loop, or use `@EntityGraph` / `JOIN FETCH` in the `@Query` to fetch them in one query.",
        "bl.db.page_size_too_large": "Reject page sizes larger than server max (e.g., 100). Return 400 Bad Request if the client asks for more.",
        "bl.db.log_entity": "Log only the entity ID and operation, never the full entity. If you must log details, mask PII fields (email, phone, SSN) explicitly.",
    }
    return fixes.get(rule_id, "Optimize the DB access pattern: reduce round-trips, narrow the projection, or add appropriate locking.")


def _get_java_bl_fix(rule_id: str) -> str:
    """Fix suggestions for v7.3.1 Java/Spring business-logic findings."""
    fixes = {
        "bl.java.parallel_stream_in_request": "Replace `.parallelStream()` with a dedicated executor: `executor.submit(() -> ...)`. Configure ThreadPoolExecutor with bounded queue and max threads.",
        "bl.java.collectors_tomap_no_merge": "Add a merge function as the 3rd arg: `Collectors.toMap(keyFn, valFn, (a, b) -> a)` to keep the first, or `(a, b) -> b` to keep the last.",
        "bl.java.stream_consumed_twice": "Streams are single-use. Either re-create the stream (`list.stream()...` again) or collect to a List first and iterate the List multiple times.",
        "bl.java.optional_chain_get": "Replace `.get()` with `.orElse(default)` or `.orElseThrow(() -> new NotFoundException())`. If you genuinely checked isPresent(), refactor to `if (opt.isPresent()) { opt.get(); }`.",
        "bl.java.swallow_exception_return_null": "Don't catch Exception and return null. Either: (a) catch specific exceptions and return Optional.empty(), (b) rethrow as a domain exception with context, or (c) let it propagate to a global @ExceptionHandler.",
        "bl.java.catch_log_rethrow": "Either log OR rethrow, not both. If you must add context, wrap: `throw new DomainException(\"operation failed for id=\" + id, e)`. Don't log + rethrow the same exception.",
        "bl.java.sync_http_in_request": "Use WebClient (reactive, non-blocking) or wrap RestTemplate in @Async + CompletableFuture. Return 202 Accepted and let the client poll for results.",
        "bl.java.loop_size_grows": "Cache the size before the loop: `int n = list.size(); for (int i = 0; i < n; i++)`. Or use a for-each loop: `for (var x : list)`.",
        "bl.java.stream_for_each_side_effect": "Use `.collect(Collectors.toList())` for accumulation. If mutation is required, use `.forEachOrdered()` and ensure the collection is synchronized.",
        "bl.java.transactional_private_method": "Make the method `public`. Spring's CGLIB proxy only intercepts public methods. Alternatively, use AspectJ load-time weaving for private-method transactions.",
        "bl.java.transactional_self_invocation": "Inject the bean as a field: `@Autowired private MyService self;` then call `self.method()`. Or use `AopContext.currentProxy()` (requires `@EnableAspectJAutoProxy(exposeProxy = true)`).",
        "bl.java.interrupted_not_restored": "Add `Thread.currentThread().interrupt();` as the first line of the catch block. This restores the interrupt flag so the thread pool can shut down cleanly.",
        "bl.java.collect_size_zero": "Replace `.collect(toList()).size() == 0` with `.collect(toList()).isEmpty()`. Or better: `.findAny().isPresent()` (short-circuits on first match).",
        "bl.java.multiple_findbyid": "Replace 3+ `findById()` calls with one `findAllById(List.of(id1, id2, id3))` — single `SELECT ... WHERE id IN (...)` query.",
        "bl.java.stream_count_zero": "Replace `.count() == 0` with `.findAny().isEmpty()` (short-circuits) or `.noneMatch(predicate)` (semantically clearer).",
        "bl.java.collect_then_foreach": "Remove the `.collect(toList())` and call `.forEach(...)` directly on the stream. Only collect if you need the List elsewhere.",
    }
    return fixes.get(rule_id, "Refactor the Java/Spring pattern per the message recommendation.")


def scan_repo_business_logic(repo_root: Path, max_files: int = 500) -> List[Finding]:
    """Scan a repository for business logic bugs.

    Detects:
      - Negative quantity/amount in arithmetic (refund exploit)
      - Missing balance check before withdrawal
      - Price/discount/tax from user input without validation
      - Score/rating from user input without range check
      - Quantity/stock update without non-negative check
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
            findings.extend(scan_python_business_logic(p, repo_root))
            file_count += 1
        elif ext == '.java':
            findings.extend(scan_java_business_logic(p, repo_root))
            file_count += 1
        elif ext in ('.js', '.ts'):
            findings.extend(scan_js_business_logic(p, repo_root))
            file_count += 1

    return findings
