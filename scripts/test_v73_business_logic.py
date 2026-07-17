#!/usr/bin/env python3
"""End-to-end test for v7.3 additions: business_logic_miner DB patterns + codebase_understanding dead-persistence."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from loomscan.business_logic_miner import scan_repo_business_logic
from loomscan.codebase_understanding import analyze_codebase, detect_dead_persistence, index_codebase


# Test fixture: Java code containing each bl.db.* pattern
JAVA_SAMPLE = """\
package com.example;

import org.springframework.web.bind.annotation.*;
import org.springframework.data.domain.*;
import java.util.*;

@RestController
public class OrderController {

    private final OrderRepository orderRepository;
    private final UserRepository userRepository;

    public OrderController(OrderRepository or, UserRepository ur) {
        this.orderRepository = or;
        this.userRepository = ur;
    }

    // bl.db.load_all_for_count
    public int countOrders() {
        List<Order> orders = orderRepository.findAll();
        return orders.size();
    }

    // bl.db.load_entity_for_one_field
    public String getUserEmail(Long id) {
        User u = userRepository.findById(id).orElse(null);
        return u.getEmail();
    }

    // bl.db.load_all_then_filter
    public Order findActiveOrder() {
        List<Order> all = orderRepository.findAll();
        for (Order o : all) {
            if (o.isActive()) return o;
        }
        return null;
    }

    // bl.db.load_all_then_stream_filter
    public Order findByNameStream(String name) {
        return orderRepository.findAll().stream()
            .filter(o -> o.getName().equals(name))
            .findFirst()
            .orElse(null);
    }

    // bl.db.load_all_for_contains
    public boolean hasOrder(Order target) {
        return orderRepository.findAll().contains(target);
    }

    // bl.db.save_unchanged
    public void noopSave(Long id) {
        User u = userRepository.findById(id).orElse(null);
        userRepository.save(u);
    }

    // bl.db.exists_then_find
    public User getUserIfPresent(Long id) {
        if (userRepository.existsById(id)) {
            return userRepository.findById(id).orElse(null);
        }
        return null;
    }

    // bl.db.count_then_findall
    public List<Order> listIfAny() {
        long c = orderRepository.count();
        if (c > 0) {
            return orderRepository.findAll();
        }
        return Collections.emptyList();
    }

    // bl.db.read_modify_write_no_lock
    public void updateEmail(Long id, String email) {
        User u = userRepository.findById(id).orElse(null);
        u.setEmail(email);
        userRepository.save(u);
    }

    // bl.db.unpaginated_endpoint
    @GetMapping("/orders")
    public List<Order> listOrders() {
        return orderRepository.findAll();
    }

    // bl.db.n_plus_1_in_loop
    public Map<Long, String> getUserEmails(List<Order> orders) {
        Map<Long, String> result = new HashMap<>();
        for (Order o : orders) {
            User u = userRepository.findById(o.getUserId()).orElse(null);
            result.put(o.getId(), u.getEmail());
        }
        return result;
    }

    // bl.db.page_size_too_large
    public List<Order> listAllAtOnce() {
        return orderRepository.findAll(PageRequest.of(0, Integer.MAX_VALUE)).getContent();
    }

    // bl.db.log_entity
    public void debugLog(Long id) {
        log.info(userRepository.findById(id).orElse(null));
    }

    // bl.db.uncached_lookup (suppressed if @Cacheable present)
    public User getCachedUser(Long id) {
        return userRepository.findById(id).orElse(null);
    }

    // bl.db.exists_then_save
    public void createUserIfMissing(String email) {
        if (!userRepository.existsByEmail(email)) {
            userRepository.save(new User(email));
        }
    }

    // bl.db.delete_then_insert
    public void reInsert(Long id) {
        Order o = orderRepository.findById(id).orElse(null);
        orderRepository.delete(o);
        orderRepository.save(new Order(o.getName()));
    }

    // bl.db.load_all_for_anymatch
    public boolean anyMatching(String name) {
        return orderRepository.findAll().stream().anyMatch(o -> o.getName().equals(name));
    }

    // Non-violating baseline (should produce NO findings)
    public Order getOrderById(Long id) {
        return orderRepository.findById(id).orElseThrow(() -> new RuntimeException("not found"));
    }
}
"""


def write_fixture(tmp: Path) -> Path:
    repo = tmp / "demo"
    repo.mkdir()
    src = repo / "src" / "main" / "java" / "com" / "example"
    src.mkdir(parents=True)
    (src / "OrderController.java").write_text(JAVA_SAMPLE)
    return repo


def test_bl_db_patterns(tmp: Path) -> int:
    print("=" * 70)
    print("TEST 1: business_logic_miner DB patterns")
    print("=" * 70)
    repo = write_fixture(tmp)
    findings = scan_repo_business_logic(repo, max_files=50)

    # Group findings by rule_id
    by_rule: dict[str, int] = {}
    for f in findings:
        rid = f.rule_id.replace("L0.", "")
        by_rule[rid] = by_rule.get(rid, 0) + 1

    expected_rules = {
        "bl.db.load_all_for_count",
        "bl.db.load_entity_for_one_field",
        "bl.db.load_all_then_filter",
        "bl.db.load_all_then_stream_filter",
        "bl.db.load_all_for_contains",
        "bl.db.save_unchanged",
        "bl.db.exists_then_find",
        "bl.db.count_then_findall",
        "bl.db.read_modify_write_no_lock",
        "bl.db.unpaginated_endpoint",
        "bl.db.n_plus_1_in_loop",
        "bl.db.page_size_too_large",
        "bl.db.log_entity",
        "bl.db.exists_then_save",
        "bl.db.delete_then_insert",
        "bl.db.load_all_for_anymatch",
    }

    failures = 0
    print(f"Total findings: {len(findings)}")
    print(f"Unique rule_ids detected: {sorted(by_rule.keys())}")
    for expected in sorted(expected_rules):
        if expected in by_rule:
            print(f"  ✅ {expected}: {by_rule[expected]} hit(s)")
        else:
            print(f"  ❌ {expected}: NOT DETECTED")
            failures += 1
    return failures


def test_dead_persistence(tmp: Path) -> int:
    print("\n" + "=" * 70)
    print("TEST 2: codebase_understanding dead-persistence detection")
    print("=" * 70)

    # Build a fixture where "AuditLog" entity is only written, never read.
    # "User" is both written and read, so should NOT be flagged.
    java_code = """\
package com.example;

public class AuditService {
    private AuditLogRepository auditRepo;
    private UserRepository userRepo;

    public void recordEvent(String event) {
        auditRepo.save(new AuditLog(event));
        auditRepo.save(new AuditLog(event + " v2"));
    }

    public void updateUserEmail(Long id, String email) {
        User u = userRepo.findById(id).orElse(null);
        if (u != null) {
            u.setEmail(email);
            userRepo.save(u);
        }
    }
}
"""
    repo = tmp / "dead"
    repo.mkdir()
    src = repo / "AuditService.java"
    src.write_text(java_code)

    model = index_codebase(repo, max_files=10)
    print(f"Indexed {len(model.functions)} function(s)")
    print(f"Entity types written across all functions: {sorted({e for f in model.functions for e in f.entity_types_written})}")
    print(f"Entity types read across all functions:    {sorted({e for f in model.functions for e in f.entity_types_read})}")

    dead = detect_dead_persistence(model)
    print(f"\nDead-persistence findings: {len(dead)}")
    for d in dead:
        print(f"  - {d.rule_id}: {d.description}")

    failures = 0
    # AuditLog should be flagged as dead (only written, never read)
    if not any(d.rule_id == "CU.DB-DEAD-PERSISTENCE" and "AuditLog" in d.description for d in dead):
        print("  ❌ FAIL: AuditLog should be flagged as dead persistence")
        failures += 1
    else:
        print("  ✅ AuditLog correctly flagged as dead persistence")
    # User should NOT be flagged (it is both written and read)
    if any(d.rule_id == "CU.DB-DEAD-PERSISTENCE" and "User" in d.description for d in dead):
        print("  ❌ FAIL: User should NOT be flagged (it has a read path)")
        failures += 1
    else:
        print("  ✅ User correctly NOT flagged (has read path)")
    return failures


def test_analyze_codebase_end_to_end(tmp: Path) -> int:
    print("\n" + "=" * 70)
    print("TEST 3: analyze_codebase() end-to-end")
    print("=" * 70)
    java_code = """\
public class OrderService {
    private OrderRepository orderRepo;
    public void saveOrder() {
        orderRepo.save(new Order("a"));
        orderRepo.save(new Order("b"));
        orderRepo.save(new Order("c"));
    }
}
"""
    repo = tmp / "e2e"
    repo.mkdir()
    (repo / "OrderService.java").write_text(java_code)

    model, findings = analyze_codebase(repo)
    cu_findings = [f for f in findings if f.rule_id.startswith("CU.")]
    print(f"Total CU findings: {len(cu_findings)}")
    for f in cu_findings:
        print(f"  - {f.rule_id}: {f.description[:100]}")
    if any(f.rule_id == "CU.DB-DEAD-PERSISTENCE" and "Order" in f.description for f in cu_findings):
        print("  ✅ Order flagged as dead persistence via analyze_codebase()")
        return 0
    print("  ❌ FAIL: Order not flagged as dead persistence via analyze_codebase()")
    return 1


def main():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        failures = 0
        failures += test_bl_db_patterns(tmp)
        failures += test_dead_persistence(tmp)
        failures += test_analyze_codebase_end_to_end(tmp)

    print("\n" + "=" * 70)
    if failures == 0:
        print("✅ ALL v7.3 BUSINESS-LOGIC & DEAD-PERSISTENCE TESTS PASSED")
        sys.exit(0)
    else:
        print(f"❌ {failures} test failure(s)")
        sys.exit(1)


if __name__ == "__main__":
    main()
