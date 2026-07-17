#!/usr/bin/env python3
"""v7.3.4 regression test for bl.db.write_in_loop suppression scope.

The v7.3.3 implementation used a ±1500 char context window for suppression,
which spanned multiple Java methods. If ANY method in the file used saveAll(),
ALL write_in_loop findings in the file were suppressed — including legitimate
ones in different methods.

This test verifies the v7.3.4 fix: suppression is now scoped to the matched
loop body ONLY.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from loomscan.business_logic_miner import scan_repo_business_logic


# Test fixture: a file with TWO methods:
#   1. bulkSaveCorrect() — uses saveAll() correctly (no save() in loop)
#   2. bulkSaveBad() — uses save() in a for-loop (should fire)
#
# In v7.3.3: both methods were in the same file, so the saveAll() in method 1
#   incorrectly suppressed the finding in method 2. Result: 0 findings.
# In v7.3.4: suppression is scoped to the loop body. Method 2's loop body
#   does NOT contain saveAll, so the finding fires. Result: 1 finding.
JAVA_CODE = """\
package com.example;

import org.springframework.web.bind.annotation.*;
import java.util.*;

@RestController
public class MixedController {

    private final UserRepository userRepo;

    public MixedController(UserRepository r) { this.userRepo = r; }

    // GOOD: uses saveAll() correctly — no save() in loop
    @PostMapping("/bulk-correct")
    public void bulkSaveCorrect(List<User> users) {
        // No loop here — just a single saveAll call
        userRepo.saveAll(users);
    }

    // BAD: save() inside a for-loop — should fire bl.db.write_in_loop
    @PostMapping("/bulk-bad")
    public void bulkSaveBad(List<User> users) {
        for (int i = 0; i < users.size(); i++) {
            User u = users.get(i);
            u.setEmail(u.getEmail().toLowerCase());
            userRepo.save(u);  // <-- N+1 write
        }
    }

    // GOOD: save() in loop BUT saveAll is also in the SAME loop body
    // (unusual pattern, but should be suppressed since batch API is present)
    @PostMapping("/mixed-same-loop")
    public void mixedSameLoop(List<User> users) {
        for (User u : users) {
            // Both save() and saveAll() in the same loop body — suppress
            userRepo.save(u);
            userRepo.saveAll(users);
        }
    }
}
"""


def main():
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td) / "demo"
        (repo / "src").mkdir(parents=True)
        (repo / "src" / "MixedController.java").write_text(JAVA_CODE)

        findings = scan_repo_business_logic(repo, max_files=50)
        write_in_loop_findings = [f for f in findings if "write_in_loop" in f.rule_id]

        print(f"Total findings: {len(findings)}")
        print(f"bl.db.write_in_loop findings: {len(write_in_loop_findings)}")
        for f in write_in_loop_findings:
            print(f"  - line {f.start_line}: {f.message[:80]}")

        # Expected: 1 finding (from bulkSaveBad)
        # - bulkSaveCorrect: no save() in loop → no match → no finding
        # - bulkSaveBad: save() in loop, no saveAll in loop body → fires
        # - mixedSameLoop: save() in loop BUT saveAll also in loop body → suppressed
        if len(write_in_loop_findings) == 1:
            print(f"\n✅ PASS: exactly 1 write_in_loop finding (suppression correctly scoped)")
            print(f"   v7.3.3 would have produced 0 findings (suppression window too wide)")
            return 0
        elif len(write_in_loop_findings) == 0:
            print(f"\n❌ FAIL: 0 findings — suppression bug still present (v7.3.3 behavior)")
            return 1
        else:
            print(f"\n❌ FAIL: {len(write_in_loop_findings)} findings — expected 1")
            print(f"   The mixed-same-loop case may be firing when it should be suppressed")
            return 1


if __name__ == "__main__":
    sys.exit(main())
