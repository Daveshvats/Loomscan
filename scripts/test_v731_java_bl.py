#!/usr/bin/env python3
"""Test the v7.3.1 Java/Spring BL-miner patterns."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from loomscan.business_logic_miner import scan_repo_business_logic


JAVA_SAMPLE = """\
package com.example;

import org.springframework.web.bind.annotation.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.*;

@RestController
public class DemoController {

    @GetMapping("/test")
    public String parallelStream() {
        List<Integer> nums = List.of(1, 2, 3);
        return nums.parallelStream().map(String::valueOf).collect(Collectors.joining(","));
    }

    @GetMapping("/tomap")
    public Map<String, Integer> toMapNoMerge() {
        return List.of("a", "b", "a").stream()
            .collect(Collectors.toMap(s -> s, s -> 1));
    }

    @GetMapping("/optional")
    public String optionalGet() {
        return List.of(1, 2, 3).stream()
            .filter(n -> n > 5)
            .findFirst()
            .get()
            .toString();
    }

    @GetMapping("/swallow")
    public String swallow() {
        try {
            risky();
            return "ok";
        } catch (Exception e) {
            return null;
        }
    }

    @GetMapping("/sync-http")
    public String syncHttp() {
        return restTemplate.getForObject("https://api.example.com/data", String.class);
    }

    @GetMapping("/loop-grow")
    public List<Integer> loopGrow() {
        List<Integer> list = new ArrayList<>(List.of(1, 2));
        for (int i = 0; i < list.size(); i++) {
            list.add(i);
        }
        return list;
    }

    @GetMapping("/tx-private")
    public String txPrivate() {
        return doWork();
    }

    @Transactional
    private String doWork() {
        return "done";
    }

    @GetMapping("/multiple-find")
    public String multipleFind() {
        User u1 = userRepo.findById(1L).orElse(null);
        User u2 = userRepo.findById(2L).orElse(null);
        User u3 = userRepo.findById(3L).orElse(null);
        return u1 + "" + u2 + u3;
    }

    @GetMapping("/stream-count")
    public boolean streamCount() {
        return list.stream().filter(x -> x > 0).count() == 0;
    }

    @GetMapping("/collect-foreach")
    public void collectThenForEach() {
        list.stream()
            .filter(x -> x > 0)
            .collect(Collectors.toList())
            .forEach(System.out::println);
    }

    @GetMapping("/self-invoke")
    @Transactional
    public String publicMethod() {
        if (someCondition) {
            return this.publicMethod();  // self-invocation
        }
        return "tx";
    }

    @GetMapping("/interrupted")
    public String interrupted() throws InterruptedException {
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            // forgot to restore interrupt
        }
        return "ok";
    }
}
"""


def main():
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir) / "demo"
        (repo / "src").mkdir(parents=True)
        (repo / "src" / "DemoController.java").write_text(JAVA_SAMPLE)

        findings = scan_repo_business_logic(repo, max_files=50)
        by_rule = {}
        for f in findings:
            rid = f.rule_id.replace("L0.", "")
            by_rule[rid] = by_rule.get(rid, 0) + 1

        print(f"Total findings: {len(findings)}")
        print(f"Unique rule_ids: {sorted(by_rule.keys())}")

        expected_rules = {
            "bl.java.parallel_stream_in_request",
            "bl.java.collectors_tomap_no_merge",
            "bl.java.optional_chain_get",
            "bl.java.swallow_exception_return_null",
            "bl.java.sync_http_in_request",
            "bl.java.loop_size_grows",
            "bl.java.transactional_private_method",
            "bl.java.multiple_findbyid",
            "bl.java.stream_count_zero",
            "bl.java.collect_then_foreach",
            "bl.java.transactional_self_invocation",
            "bl.java.interrupted_not_restored",
        }

        failures = 0
        for expected in sorted(expected_rules):
            if expected in by_rule:
                print(f"  OK   {expected}: {by_rule[expected]} hit(s)")
            else:
                print(f"  MISS {expected}: NOT DETECTED")
                failures += 1

        if failures:
            print(f"\n{failures} test failure(s)")
            sys.exit(1)
        print(f"\nAll {len(expected_rules)} expected Java BL patterns detected")


if __name__ == "__main__":
    main()
