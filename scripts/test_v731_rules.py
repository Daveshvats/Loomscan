#!/usr/bin/env python3
"""Verify all v7.3.1 rules load and detect correctly."""
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

    # Try to compile each pattern
    compile_failures = []
    for r in rules:
        rid = r.get("id", "")
        pat = r.get("pattern", "")
        try:
            re.compile(pat)
        except re.error as e:
            compile_failures.append((rid, pat, str(e)))
            print(f"  FAIL: {rid}: {e}")

    if compile_failures:
        print(f"\n{len(compile_failures)} patterns failed to compile")
        sys.exit(1)
    print(f"All {len(rules)} patterns compile successfully")

    # Functional test for the fixed rules + new rules
    print("\n--- Functional detection test ---")
    samples = {
        # Fixed rules from v7.3
        "java-enum-valueof-without-validation": [
            ('EmailTrigger.valueOf(triggerType);', True),
            ('Status.valueOf(input);', True),
            ('Enum.valueOf(MyEnum.class, name);', True),
            ('String.valueOf(obj);', False),
            ('Integer.valueOf("123");', False),
        ],
        "java-sync-blocking-endpoint-no-timeout": [
            ('@PostMapping("/upload")', True),
            ('@PostMapping("/api/files/import")', True),
            ('@PutMapping("/reports/generate")', True),
            ('@GetMapping("/list")', False),
        ],
        "java-sync-endpoint-with-requestbody-no-async": [
            ('@PostMapping("/orders")', True),
            ('@GetMapping("/orders")', False),
        ],
        # v7.3.1 new rules — sample tests
        "leak-static-collection-grow": [
            ('private static final Map<String, Object> CACHE = new HashMap<>();', True),
        ],
        "leak-threadlocal-no-remove": [
            ('private static ThreadLocal<SimpleDateFormat> tl = new ThreadLocal<>();', True),
        ],
        "leak-static-simpledateformat": [
            ('private static final SimpleDateFormat FMT = new SimpleDateFormat("yyyy");', True),
        ],
        "ts-shared-mutable-state": [
            ('static List<String> list = new ArrayList<>();', True),
        ],
        "ts-simpledateformat-shared": [
            ('SimpleDateFormat fmt = new SimpleDateFormat("yyyy");', True),
        ],
        "ts-stringbuilder-shared": [
            ('static StringBuilder sb = new StringBuilder();', True),
        ],
        "ts-double-checked-locking": [
            ('if (instance == null) { synchronized (lock) {', True),
        ],
        "ts-synchronized-on-this": [
            ('synchronized (this) {', True),
        ],
        "ts-synchronized-on-string": [
            ('synchronized ("lock") {', True),
        ],
        "ts-notify-instead-of-notifyall": [
            ('object.notify();', True),
        ],
        "null-optional-get-without-check": [
            ('optional.get();', True),
        ],
        "null-findfirst-get": [
            ('stream.findFirst().get();', True),
        ],
        "null-string-equality-identity": [
            ('if (str == "hello") {', True),
        ],
        "null-autoboxing-unbox": [
            ('int count = map.get("count");', True),
        ],
        "exc-catch-exception-too-broad": [
            ('catch (Exception e) {', True),
        ],
        "exc-catch-throwable": [
            ('catch (Throwable t) {', True),
        ],
        "exc-empty-catch-block": [
            ('catch (Exception e) {}', True),
        ],
        "exc-printstacktrace": [
            ('e.printStackTrace();', True),
        ],
        "exc-system-out-println": [
            ('System.out.println("debug");', True),
        ],
        "exc-return-in-finally": [
            ('finally { return result; }', True),
        ],
        "resource-try-finally-not-twr": [
            ('try { fis.read(); } finally { fis.close(); }', True),
        ],
        "resource-connection-not-twr": [
            ('Connection conn = dataSource.getConnection();', True),
        ],
        "spring-autowired-field-injection": [
            ('@Autowired private UserService userService;', True),
        ],
        "spring-value-for-secret": [
            ('@Value("${password}")', True),
            ('@Value("${app.name}")', False),
        ],
        "val-requestbody-string-unbounded": [
            ('public ResponseEntity upload(@RequestBody String body) {', True),
        ],
        "val-email-no-validation": [
            ('private String email;', True),
        ],
        "conc-wait-without-while": [
            ('if (!ready) { obj.wait(); }', True),
        ],
        "conc-fixedthreadpool-unbounded-queue": [
            ('Executors.newFixedThreadPool(10);', True),
        ],
        "conc-cachedthreadpool-unbounded": [
            ('Executors.newCachedThreadPool();', True),
        ],
        "str-concat-in-loop": [
            ('for (String s : list) { result += "x"; }', True),
        ],
        "coll-arrays-as-list-modify": [
            ('Arrays.asList(arr).add(x);', True),
        ],
        "io-readalllines-large-file": [
            ('List<String> lines = Files.readAllLines(path);', True),
        ],
        "io-getbytes-no-charset": [
            ('byte[] b = str.getBytes();', True),
        ],
        "time-new-date-for-now": [
            ('Date now = new Date();', True),
        ],
        "time-simpledateformat-no-locale": [
            ('new SimpleDateFormat("yyyy-MM-dd");', True),
        ],
        "log-string-concat": [
            ('log.info("user " + userId + " logged in");', True),
        ],
        "http-cors-allow-all": [
            ('allowedOrigins = "*";', True),
        ],
        "http-csrf-disabled": [
            ('csrf().disable();', True),
        ],
        "http-ssl-trust-all": [
            ('TrustAllCerts trustAll = new TrustAllCerts();', True),
        ],
        "sec-permit-all": [
            ('.permitAll();', True),
        ],
        "sec-any-request-permit-all": [
            ('anyRequest().permitAll();', True),
        ],
        "sec-password-encoder-noop": [
            ('PasswordEncoder noop = NoOpPasswordEncoder.getInstance();', True),
        ],
        "ser-objectinputstream": [
            ('ObjectInputStream ois = new ObjectInputStream(is);', True),
        ],
        "refl-class-forname-variable": [
            ('Class<?> c = Class.forName(userInput);', True),
            ('Class<?> c = Class.forName("com.example.Foo");', False),
        ],
        "jndi-initialcontext-variable": [
            ('Object o = new InitialContext().lookup(userInput);', True),
        ],
    }

    by_id = {r["id"]: r for r in rules}
    failures = 0
    for rid, cases in samples.items():
        if rid not in by_id:
            print(f"  WARN: RULE NOT FOUND: {rid}")
            failures += 1
            continue
        pat = by_id[rid]["pattern"]
        try:
            regex = re.compile(pat)
        except re.error as e:
            print(f"  FAIL {rid}: compile error: {e}")
            failures += 1
            continue
        for line, expected in cases:
            matched = bool(regex.search(line))
            mark = "OK" if matched == expected else "FAIL"
            if matched != expected:
                failures += 1
                print(f"  {mark} {rid}: line={line!r} expected={expected} got={matched}")

    if failures:
        print(f"\n{failures} test failures")
        sys.exit(1)
    print(f"\nAll functional tests passed ({len(samples)} rules tested)")


if __name__ == "__main__":
    main()
