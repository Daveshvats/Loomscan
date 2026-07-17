#!/usr/bin/env python3
"""Verify all v7.3 rules added to java-production-incidents.yml load and detect correctly."""
import re
import sys
import yaml
from pathlib import Path

PACK = Path(__file__).resolve().parent.parent / "loomscan" / "rules" / "packs" / "java-production-incidents.yml"

def main():
    text = PACK.read_text()
    data = yaml.safe_load(text)
    rules = data.get("rules", [])
    print(f"Total rules in pack: {len(rules)}")

    # Find all v7.3 rules (sections 31-45)
    v73_ids = []
    compile_failures = []
    for r in rules:
        rid = r.get("id", "")
        if rid.startswith(("java-enum-valueof", "java-sync-blocking", "java-multipart-endpoint",
                           "java-resttemplate-no-timeout", "java-webclient-no-timeout",
                           "java-httpclient-no-timeout", "java-thread-sleep-in-request",
                           "java-jackson-coerce", "java-uuid-fromstring",
                           "perf-transactional", "perf-db-read-unused", "perf-findall-then",
                           "perf-jpql-select-star", "perf-native-query-select-star",
                           "perf-jdbc-select-star", "perf-fetch-join-no-where",
                           "perf-count-then-findall", "perf-exists-then-find",
                           "perf-entitymanager", "perf-jpa-modifying",
                           "perf-onetomany", "perf-elementcollection",
                           "perf-column-no-length", "perf-lob-no-fetch",
                           "perf-pessimistic", "perf-select-for-update",
                           "perf-version-no", "perf-hibernate",
                           "perf-jdbctemplate-no-batchsize", "perf-statement-no-pool",
                           "perf-resultset-not-closed", "perf-save-and-flush",
                           "perf-delete-then-insert", "perf-save-in-loop-regex",
                           "perf-update-set-no-where", "perf-delete-from-no-where",
                           "perf-cacheable", "perf-hibernate-ddl-auto",
                           "perf-hibernate-show-sql", "perf-hibernate-format-sql",
                           "perf-jpa-query-like-leading", "perf-jpa-query-or-in-where",
                           "perf-jpa-query-not-in", "perf-jpa-query-distinct",
                           "perf-spring-data-method-name", "perf-spring-data-findby",
                           "perf-soft-delete-no-index", "perf-no-audit-listener",
                           "perf-flyway-baseline", "perf-liquibase-drop-first")):
            v73_ids.append(rid)

    print(f"v7.3 rules found: {len(v73_ids)}")
    for rid in v73_ids:
        print(f"  - {rid}")

    # Try to compile each pattern
    print("\n--- Compile check ---")
    for r in rules:
        rid = r.get("id", "")
        if rid not in v73_ids:
            continue
        pat = r.get("pattern", "")
        try:
            re.compile(pat)
        except re.error as e:
            compile_failures.append((rid, pat, str(e)))
            print(f"  ❌ FAIL: {rid}: {e}")

    if compile_failures:
        print(f"\n❌ {len(compile_failures)} patterns failed to compile")
        sys.exit(1)
    print(f"\n✅ All {len(v73_ids)} v7.3 patterns compile successfully")

    # Functional test: run each rule against sample code and verify detection
    print("\n--- Functional detection test ---")
    samples = {
        "java-enum-valueof-without-validation": [
            ('EmailTrigger.valueOf(triggerType);', True),
            ('String.valueOf(obj);', False),  # String.valueOf not flagged
            ('Integer.valueOf("123");', False),  # Integer.valueOf with literal not flagged
        ],
        "java-sync-blocking-endpoint-no-timeout": [
            ('@PostMapping("/upload")', True),
            ('@GetMapping("/list")', False),
        ],
        "java-multipart-endpoint-no-async": [
            ('public ResponseEntity upload(@RequestParam MultipartFile file) {', True),
            ('public ResponseEntity upload(@RequestParam String name) {', False),
        ],
        "java-resttemplate-no-timeout": [
            ('RestTemplate rt = new RestTemplate();', True),
            ('RestTemplate rt = new RestTemplateBuilder().build();', False),
        ],
        "java-thread-sleep-in-request": [
            ('Thread.sleep(5000);', True),
            ('ScheduledExecutor.delay(5);', False),
        ],
        "java-uuid-fromstring-no-try": [
            ('UUID id = UUID.fromString(userInput);', True),
            ('UUID id = UUID.randomUUID();', False),
        ],
        "perf-transactional-no-readonly": [
            ('@Transactional(isolation = Isolation.READ_COMMITTED)', True),
            ('@Transactional(readOnly = true)', False),
            ('@Transactional(propagation = Propagation.REQUIRES_NEW)', False),
        ],
        "perf-transactional-bare-default": [
            ('@Transactional', True),
            ('@Transactional(readOnly = true)', False),
        ],
        "perf-transactional-required-nested": [
            ('@Transactional(propagation = Propagation.REQUIRED)', True),
            ('@Transactional(propagation = Propagation.REQUIRES_NEW)', False),
        ],
        "perf-db-read-unused-result": [
            ('        repository.findById(id);', True),
            ('        User user = repository.findById(id);', False),
        ],
        "perf-findall-then-size": [
            ('int count = repository.findAll().size();', True),
            ('int count = (int) repository.count();', False),
        ],
        "perf-findall-then-stream": [
            ('repository.findAll().stream().filter(...)', True),
            ('repository.findAllById(ids).stream()', False),
        ],
        "perf-jpql-select-star": [
            ('@Query("SELECT * FROM User u")', True),
            ('@Query("SELECT u.id FROM User u")', False),
        ],
        "perf-native-query-select-star": [
            ('em.createNativeQuery("SELECT * FROM users")', True),
            ('em.createNativeQuery("SELECT id FROM users")', False),
        ],
        "perf-fetch-join-no-where": [
            ('@Query("SELECT u FROM User u JOIN FETCH u.orders")', True),
            ('@Query("SELECT u FROM User u JOIN FETCH u.orders WHERE u.id = :id")', False),
        ],
        "perf-exists-then-find": [
            ('if (repo.existsById(id) || false) { repo.findById(id); }', True),
            ('if (repo.findById(id).isPresent()) { ... }', False),
        ],
        "perf-entitymanager-merge-new-entity": [
            ('em.merge(new User());', True),
            ('em.merge(detachedUser);', False),
        ],
        "perf-jpa-modifying-query-without-modifying": [
            ('@Query("UPDATE User u SET u.status = 1")', True),
            ('@Query("SELECT u FROM User u")', False),
        ],
        "perf-onetomany-no-mappedby": [
            ('@OneToMany(cascade = CascadeType.ALL)', True),
            ('@OneToMany(mappedBy = "user")', False),
        ],
        "perf-elementcollection-no-fetch": [
            ('@ElementCollection', True),
            ('@ElementCollection(fetch = FetchType.LAZY)', False),
        ],
        "perf-lob-no-fetch-lazy": [
            ('@Lob private byte[] data;', True),
            ('@Lob @Basic(fetch = FetchType.LAZY) private byte[] data;', False),
        ],
        "perf-pessimistic-lock-no-timeout": [
            ('LockModeType.PESSIMISTIC_WRITE', True),
            ('LockModeType.OPTIMISTIC', False),
        ],
        "perf-hibernate-query-iterate": [
            ('query.iterate()', True),
            ('query.list()', False),
        ],
        "perf-save-and-flush-unnecessary": [
            ('repo.saveAndFlush(user)', True),
            ('repo.save(user)', False),
        ],
        "perf-save-in-loop-regex": [
            ('for (User u : users) { repo.save(u); }', True),
            ('repo.save(user);', False),
        ],
        "perf-delete-from-no-where": [
            ('"DELETE FROM users"', True),
            ('"DELETE FROM users WHERE id = ?"', False),
        ],
        "perf-update-set-no-where": [
            ('"UPDATE users SET status = 1;"', True),
            ('"UPDATE users SET status = 1 WHERE id = ?"', False),
        ],
        "perf-hibernate-ddl-auto-update": [
            ('spring.jpa.hibernate.ddl-auto=update', True),
            ('spring.jpa.hibernate.ddl-auto=validate', False),
        ],
        "perf-spring-data-findby-containing": [
            ('findByNameContaining(name)', True),
            ('findByName(name)', False),
        ],
        "perf-spring-data-findby-ignorecase": [
            ('findByNameIgnoreCase(name)', True),
            ('findByName(name)', False),
        ],
        "perf-jpa-query-like-leading-wildcard": [
            ('@Query("... WHERE u.name LIKE \'%name%\'")', True),
            ('@Query("... WHERE u.name LIKE \'name%\'")', False),
        ],
        "perf-soft-delete-no-index": [
            ('@Where(clause = "deleted = 0")', True),
            ('@Where(clause = "deleted = false")', False),
        ],
        "perf-flyway-baseline-on-migrate": [
            ('spring.flyway.baseline-on-migrate=true', True),
            ('spring.flyway.baseline-on-migrate=false', False),
        ],
        "perf-liquibase-drop-first": [
            ('dropAll();', True),
            ('liquibase.update();', False),
        ],
        "perf-cacheable-no-evict": [
            ('@Cacheable("users")', True),
            ('@Cacheable', False),
        ],
        "perf-resultset-not-closed-try-with-resources": [
            ('ResultSet rs = stmt.executeQuery(query);', True),
            ('try (var rs = stmt.executeQuery(query))', False),  # pattern requires "ResultSet" name
        ],
    }

    by_id = {r["id"]: r for r in rules}
    failures = 0
    for rid, cases in samples.items():
        if rid not in by_id:
            print(f"  ⚠️  RULE NOT FOUND: {rid}")
            failures += 1
            continue
        pat = by_id[rid]["pattern"]
        try:
            regex = re.compile(pat)
        except re.error as e:
            print(f"  ❌ {rid}: compile error: {e}")
            failures += 1
            continue
        for line, expected in cases:
            matched = bool(regex.search(line))
            mark = "✅" if matched == expected else "❌"
            if matched != expected:
                failures += 1
                print(f"  {mark} {rid}: line={line!r} expected_match={expected} got={matched}")
            else:
                print(f"  {mark} {rid}: line={line!r} -> {matched}")

    if failures:
        print(f"\n❌ {failures} test failures")
        sys.exit(1)
    print(f"\n✅ All functional tests passed")


if __name__ == "__main__":
    main()
