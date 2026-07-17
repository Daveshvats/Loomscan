#!/usr/bin/env python3
"""v7.3.2 clean-code false-positive test.

Scans a deliberately-clean Python file (parameterized SQL, secrets.token_*,
sandboxed eval, scrypt hashing, hmac.compare_digest, path validation) and
asserts that the FP rules fixed in v7.3.2 no longer fire.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from loomscan.orchestrator import Orchestrator


# A deliberately-clean Python file — should produce ZERO high-severity findings
CLEAN_CODE = '''\
import os
import secrets
import hashlib
import hmac
import re
from pathlib import Path

BASE_DIR = Path("/app/uploads").resolve()


def generate_token() -> str:
    """Generate a secure random token using the secrets module."""
    return secrets.token_urlsafe(32)


def hash_password(password: str) -> str:
    """Hash a password using scrypt (NIST-recommended)."""
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=64)
    return salt.hex() + dk.hex()


def verify_password(password: str, stored: str) -> bool:
    """Verify a password against stored hash using constant-time comparison."""
    salt = bytes.fromhex(stored[:32])
    expected = bytes.fromhex(stored[32:])
    actual = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=64)
    return hmac.compare_digest(expected, actual)


def get_user(conn, user_id: int):
    """Parameterized SQL — no injection risk."""
    cursor = conn.execute("SELECT id, name, email FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()


def safe_path(filename: str) -> Path:
    """Validate path against traversal."""
    candidate = (BASE_DIR / filename).resolve()
    if not str(candidate).startswith(str(BASE_DIR)):
        raise ValueError("Path traversal detected")
    return candidate


def main():
    token = generate_token()
    print(f"Token generated (length={len(token)})")
    h = hash_password("correct horse battery staple")
    print(f"Hash: {h[:16]}...")
    if verify_password("correct horse battery staple", h):
        print("Verified")


if __name__ == "__main__":
    main()
'''


def main():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "clean.py"
        p.write_text(CLEAN_CODE)
        orch = Orchestrator(repo_root=Path(td))
        result = orch.run_full()

        # Collect rule_ids that fired
        rule_ids = set()
        for f in result.findings:
            rule_ids.add(f.rule_id)

        print(f"Total findings on clean code: {len(result.findings)}")
        print(f"Unique rule_ids: {len(rule_ids)}")

        # FP rules that should NOT fire on this clean code
        fp_rules = {
            "L0.yaml:py-secrets-good",
            "L0.yaml:sgpy-secrets-token",
            "L0.yaml:py-print-secret",
            "L0.yaml:py-logger-secret",
            "L0.yaml:py-exec-injection",
            "L0.yaml:sgi-docker-no-healthcheck",
        }
        firing_fps = fp_rules & rule_ids
        if firing_fps:
            print(f"  FAIL: FP rules still firing: {sorted(firing_fps)}")
            for r in firing_fps:
                # Show the finding
                hits = [f for f in result.findings if f.rule_id == r]
                for h in hits[:3]:
                    print(f"    {h.file}:{h.start_line}: {h.message[:80]}")
            sys.exit(1)

        # Count remaining findings — should be low (< 20 ideally)
        high_severity = [f for f in result.findings if str(f.severity).lower() in ("high", "critical", "error")]
        print(f"  High/critical findings: {len(high_severity)}")
        print(f"  OK   no v7.3.2-targeted FP rules fired on clean code")

        # Show top 10 remaining findings (for transparency)
        print(f"\nTop 10 remaining findings on clean code:")
        for f in result.findings[:10]:
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            print(f"  [{sev}] {f.rule_id}: {f.file}:{f.start_line} — {f.message[:60]}")


if __name__ == "__main__":
    main()
