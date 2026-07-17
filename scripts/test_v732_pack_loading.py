#!/usr/bin/env python3
"""v7.3.2 regression test: ensure v7.3 packs are actually loaded by orchestrator.

This test exists because v7.3.0/v7.3.1 shipped with the `java-production-incidents`
pack (308 rules) and `ai-security` pack (12 rules) registered in BUILTIN_PACKS
but NEVER referenced by get_all_packs_for_files(). All v7.3 features were dead
code. This test prevents regression.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from loomscan.rules import get_all_packs_for_files, BUILTIN_PACKS


def test_java_production_incidents_loaded_for_java_files():
    """The java-production-incidents pack MUST be loaded for .java files."""
    packs = get_all_packs_for_files(["src/Main.java"])
    pack_names = [p.stem for p in packs]
    assert "java-production-incidents" in pack_names, (
        f"java-production-incidents pack NOT loaded for .java files! "
        f"Loaded packs: {pack_names}"
    )
    print(f"  OK   java-production-incidents loaded for .java files (out of {len(packs)} packs)")


def test_ai_security_always_loaded():
    """The ai-security pack MUST be loaded for ALL file types (it's multi-language)."""
    for ext in [".py", ".java", ".js", ".ts", ".go", ".rs"]:
        packs = get_all_packs_for_files([f"file{ext}"])
        pack_names = [p.stem for p in packs]
        assert "ai-security" in pack_names, (
            f"ai-security pack NOT loaded for {ext} files! "
            f"Loaded packs: {pack_names}"
        )
        print(f"  OK   ai-security loaded for {ext} files")


def test_all_builtin_packs_referenced():
    """Every pack in BUILTIN_PACKS should be referenced by get_all_packs_for_files()
    for at least one file extension. Otherwise it's dead code."""
    # Collect all extensions that trigger pack loading
    all_test_exts = [
        ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java",
        ".c", ".cpp", ".cc", ".h", ".hpp", ".rs", ".php", ".phtml",
        ".rb", ".rake", ".cs", ".vb", ".swift", ".scala", ".sc",
        ".kt", ".kts", ".sql", ".psql", ".mysql", ".ddl",
        ".sh", ".bash", ".zsh", ".ksh", ".dart", ".lua", ".r", ".R",
        ".hs", ".lhs", ".ex", ".exs", ".m", ".mm",
        ".groovy", ".gradle", ".gvy", ".gy", ".jl",
        ".pl", ".pm", ".t", ".pod", ".cob", ".cbl", ".cpy",
    ]
    loaded_packs = set()
    for ext in all_test_exts:
        packs = get_all_packs_for_files([f"file{ext}"])
        for p in packs:
            loaded_packs.add(p.stem)

    # Find unreferenced packs
    all_registered = set(BUILTIN_PACKS.keys())
    unreferenced = all_registered - loaded_packs

    # Allow some packs to be intentionally unreferenced (manual-only / experimental)
    ALLOWED_UNREFERENCED = {
        "no-secrets-in-logs",  # superseded by log-sensitive-field in java-production-incidents
    }

    truly_unreferenced = unreferenced - ALLOWED_UNREFERENCED
    assert not truly_unreferenced, (
        f"The following BUILTIN_PACKS are NEVER loaded by get_all_packs_for_files() "
        f"— they are dead code: {sorted(truly_unreferenced)}"
    )
    print(f"  OK   all {len(all_registered)} BUILTIN_PACKS are referenced ({len(loaded_packs)} unique loaded)")


def test_v73_rules_actually_fire_on_java_code():
    """End-to-end: scan a Java file with v7.3 bugs and verify the v7.3 rules fire."""
    import tempfile
    from loomscan.yaml_engine import apply_pack_to_file
    from loomscan.rules import get_builtin_pack_path

    java_code = """\
package com.example;

import org.springframework.web.bind.annotation.*;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.*;

@RestController
public class DemoController {
    @PostMapping("/upload")
    public String upload() {
        // v7.3 bug 1: Thread.sleep in request handler
        try { Thread.sleep(5000); } catch (Exception e) {}
        // v7.3 bug 2: enum.valueOf without validation
        Status s = Status.valueOf(userInput);
        // v7.3 bug 3: UUID.fromString without try/catch
        java.util.UUID id = java.util.UUID.fromString(maybeBad);
        // v7.3 bug 4: new RestTemplate() no timeout
        org.springframework.web.client.RestTemplate rt = new org.springframework.web.client.RestTemplate();
        // v7.3 bug 5: findAll().size() instead of count()
        int count = repo.findAll().size();
        return "ok";
    }
}
"""
    with tempfile.NamedTemporaryFile(suffix=".java", delete=False, mode="w") as f:
        f.write(java_code)
        java_file = f.name

    pack_path = get_builtin_pack_path("java-production-incidents")
    from pathlib import Path as _Path
    hits = apply_pack_to_file(_Path(pack_path), _Path(java_file))

    rule_ids = {h.rule_id for h in hits}
    expected_rules = {
        "java-thread-sleep-in-request",
        "java-enum-valueof-without-validation",
        "java-uuid-fromstring-no-try",
        "java-resttemplate-no-timeout",
        "perf-findall-then-size",
    }
    missing = expected_rules - rule_ids
    assert not missing, (
        f"v7.3 rules did NOT fire on planted Java bugs! Missing: {missing}. "
        f"Fired rules: {sorted(rule_ids)}"
    )
    print(f"  OK   {len(expected_rules)}/{len(expected_rules)} expected v7.3 rules fired ({len(hits)} total hits)")


def main():
    print("=" * 70)
    print("v7.3.2 regression test: pack loading + v7.3 rules fire end-to-end")
    print("=" * 70)
    failures = 0
    for test in [
        test_java_production_incidents_loaded_for_java_files,
        test_ai_security_always_loaded,
        test_all_builtin_packs_referenced,
        test_v73_rules_actually_fire_on_java_code,
    ]:
        try:
            test()
        except AssertionError as e:
            print(f"  FAIL {test.__name__}: {e}")
            failures += 1
        except Exception as e:
            print(f"  ERROR {test.__name__}: {type(e).__name__}: {e}")
            failures += 1

    print()
    if failures:
        print(f"❌ {failures} test(s) failed")
        sys.exit(1)
    print("✅ All v7.3.2 regression tests passed")


if __name__ == "__main__":
    main()
