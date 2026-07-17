#!/usr/bin/env python3
"""v7.3.3 regression test for the 4 P3 coverage gaps identified in v7.3.2 audit.

Tests:
  1. java-thread-sleep-in-request now matches Thread.sleep(50_000), Thread.sleep(var), etc.
  2. bl.db.write_in_loop BL-miner pattern catches multi-line for(...) { repo.save(x); }
  3. llm-api-key-hardcoded now matches SDK form (openai.api_key = "sk-...")
  4. llm-temperature-too-high now matches Python kwarg form (temperature=1.5)
"""
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml
from loomscan.rules import get_builtin_pack_path
from loomscan.business_logic_miner import scan_repo_business_logic


def load_rules(pack_name: str) -> dict:
    pack_path = get_builtin_pack_path(pack_name)
    with open(pack_path) as f:
        data = yaml.safe_load(f)
    return {r["id"]: r for r in data.get("rules", [])}


def test_thread_sleep_broader_pattern():
    """P3.1: Thread.sleep should match underscore/variable/computed forms."""
    print("=" * 70)
    print("P3.1: java-thread-sleep-in-request broader pattern")
    print("=" * 70)
    rules = load_rules("java-production-incidents")
    pat = rules["java-thread-sleep-in-request"]["pattern"]
    regex = re.compile(pat)

    test_cases = [
        ("Thread.sleep(5000);", True, "pure integer"),
        ("Thread.sleep(50_000);", True, "Java underscore separator"),
        ("Thread.sleep(timeout);", True, "variable arg"),
        ("Thread.sleep(TimeUnit.SECONDS.toMillis(5));", True, "computed arg"),
        ("Thread.sleep(Duration.ofSeconds(5).toMillis());", True, "Duration-based"),
        ("// Thread.sleep in comment", False, "comment — should not match (no parens on its own)"),
    ]
    failures = 0
    for code, expected, desc in test_cases:
        matched = bool(regex.search(code))
        mark = "OK" if matched == expected else "FAIL"
        if matched != expected:
            failures += 1
        print(f"  {mark} [{desc}] {code!r} -> matched={matched} expected={expected}")
    return failures


def test_write_in_loop_bl_miner():
    """P3.2: bl.db.write_in_loop should catch multi-line for(...) { repo.save(x); }"""
    print()
    print("=" * 70)
    print("P3.2: bl.db.write_in_loop (multi-line save-in-loop)")
    print("=" * 70)

    java_code = """\
package com.example;
import org.springframework.web.bind.annotation.*;
import java.util.*;

@RestController
public class DemoController {
    @PostMapping("/import")
    public void importUsers(List<User> users) {
        // Multi-line for loop with save() — the case the YAML rule misses
        for (int i = 0; i < users.size(); i++) {
            User u = users.get(i);
            u.setEmail(u.getEmail().toLowerCase());
            userRepository.save(u);
        }
    }
}
"""
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td) / "demo"
        (repo / "src").mkdir(parents=True)
        (repo / "src" / "Demo.java").write_text(java_code)
        findings = scan_repo_business_logic(repo, max_files=50)
        by_rule = {f.rule_id.replace("L0.", "") for f in findings}

        if "bl.db.write_in_loop" in by_rule:
            print(f"  OK   bl.db.write_in_loop detected multi-line save-in-loop")
            return 0
        else:
            print(f"  FAIL bl.db.write_in_loop NOT detected. Found rules: {sorted(by_rule)}")
            return 1


def test_llm_api_key_sdk_form():
    """P3.3: llm-api-key-hardcoded should match SDK form (openai.api_key = "sk-...")"""
    print()
    print("=" * 70)
    print("P3.3: llm-api-key-hardcoded SDK pattern")
    print("=" * 70)
    rules = load_rules("ai-security")
    pat = rules["llm-api-key-hardcoded"]["pattern"]
    regex = re.compile(pat)

    test_cases = [
        ('OPENAI_API_KEY="sk-proj-abcdef0123456789xyz"', True, "env-var form"),
        ("openai.api_key = 'sk-proj-abcdef0123456789xyz'", True, "Python SDK form (single quote)"),
        ('openai.api_key = "sk-proj-abcdef0123456789xyz"', True, "Python SDK form (double quote)"),
        ('anthropic.api_key = "sk-ant-api03-abcdef0123456789"', True, "Anthropic SDK form"),
        ('openai.api_key = os.environ["OPENAI_API_KEY"]', False, "SDK loading from env — should NOT match"),
        ('openai.api_key = config.api_key', False, "SDK loading from config — should NOT match"),
    ]
    failures = 0
    for code, expected, desc in test_cases:
        matched = bool(regex.search(code))
        mark = "OK" if matched == expected else "FAIL"
        if matched != expected:
            failures += 1
        print(f"  {mark} [{desc}] -> matched={matched} expected={expected}")
    return failures


def test_llm_temperature_python_kwarg():
    """P3.4: llm-temperature-too-high should match Python kwarg form (temperature=1.5)"""
    print()
    print("=" * 70)
    print("P3.4: llm-temperature-too-high Python kwarg form")
    print("=" * 70)
    rules = load_rules("ai-security")
    pat = rules["llm-temperature-too-high"]["pattern"]
    regex = re.compile(pat)

    test_cases = [
        ("temperature: 1.5", True, "JSON/dict form (colon)"),
        ("temperature=1.5", True, "Python kwarg form (equals)"),
        ("temperature=2.0", True, "Python kwarg 2.0"),
        ("temperature=0.7", False, "Safe temperature — should NOT match"),
        ("temperature: 0.5", False, "Safe temperature (colon) — should NOT match"),
        ("temperature = 1.5", True, "Python kwarg with spaces"),
    ]
    failures = 0
    for code, expected, desc in test_cases:
        matched = bool(regex.search(code))
        mark = "OK" if matched == expected else "FAIL"
        if matched != expected:
            failures += 1
        print(f"  {mark} [{desc}] {code!r} -> matched={matched} expected={expected}")
    return failures


def main():
    failures = 0
    failures += test_thread_sleep_broader_pattern()
    failures += test_write_in_loop_bl_miner()
    failures += test_llm_api_key_sdk_form()
    failures += test_llm_temperature_python_kwarg()

    print()
    print("=" * 70)
    if failures == 0:
        print("✅ All v7.3.3 P3 coverage-gap fixes verified")
        sys.exit(0)
    print(f"❌ {failures} test failure(s)")
    sys.exit(1)


if __name__ == "__main__":
    main()
