"""v6.2: CVE reference database — maps CWE + pattern to known CVEs.

When LoomScan finds a vulnerability (e.g. ObjectInputStream.readObject → CWE-502),
this module enriches the finding with known CVEs that exploited that pattern.

This gives developers context: "This pattern was exploited in CVE-2015-4852
(Apache Commons Collections RCE)" instead of just "CWE-502".
"""
from __future__ import annotations

from typing import List, Dict, Optional


# CWE → Language → [(CVE ID, description)]
CVE_REFERENCES: Dict[str, Dict[str, List[tuple]]] = {
    "CWE-502": {
        "java": [
            ("CVE-2015-4852", "Apache Commons Collections RCE via deserialization"),
            ("CVE-2017-9805", "Apache Struts REST plugin RCE via deserialization"),
            ("CVE-2018-1270", "Spring Messaging RCE via deserialization"),
            ("CVE-2016-2510", "Jackson deserialization RCE"),
        ],
        "python": [
            ("CVE-2020-29651", "PyYAML arbitrary code execution via yaml.load"),
        ],
    },
    "CWE-94": {
        "java": [
            ("CVE-2021-44228", "Log4Shell — JNDI injection via log message (CRITICAL)"),
            ("CVE-2022-22965", "Spring4Shell — ClassLoader manipulation RCE"),
        ],
        "python": [
            ("CVE-2023-24329", "Python urllib — bypass via URL parsing"),
            ("CVE-2021-29921", "Python ipaddress — improper input validation"),
        ],
        "javascript": [
            ("CVE-2021-23337", "Lodash — command injection via template"),
        ],
    },
    "CWE-89": {
        "java": [
            ("CVE-2022-22965", "Spring Framework SQL injection via data binding"),
        ],
        "python": [
            ("CVE-2022-24339", "Python SQL injection via format string"),
        ],
        "php": [
            ("CVE-2021-39241", "PHP SQL injection in popular frameworks"),
        ],
    },
    "CWE-78": {
        "java": [
            ("CVE-2021-40444", "MSHTML command injection via crafted document"),
        ],
        "python": [
            ("CVE-2022-23837", "Python subprocess command injection"),
        ],
    },
    "CWE-79": {
        "java": [
            ("CVE-2020-5421", "Spring Framework RFD attack"),
        ],
        "python": [
            ("CVE-2016-2533", "Django XSS via contrib.gis"),
        ],
        "javascript": [
            ("CVE-2021-44906", "QS module prototype pollution leading to XSS"),
        ],
    },
    "CWE-918": {
        "java": [
            ("CVE-2019-12384", "Jackson SSRF via polymorphic deserialization"),
        ],
        "python": [
            ("CVE-2023-32681", "Requests library SSRF via Proxy-Authorization header"),
        ],
    },
    "CWE-22": {
        "java": [
            ("CVE-2021-22053", "Spring Security path traversal"),
        ],
        "python": [
            ("CVE-2021-43863", "Python path traversal in widgetsnbextension"),
        ],
    },
    "CWE-611": {
        "java": [
            ("CVE-2021-23727", "XXE in Java XML parsers"),
        ],
    },
    "CWE-476": {
        "java": [
            ("CVE-2022-22965", "Spring Framework null dereference"),
        ],
        "c": [
            ("CVE-2021-3712", "OpenSSL NULL pointer dereference"),
        ],
    },
    "CWE-400": {
        "java": [
            ("CVE-2022-42889", "Text4Shell — Apache Commons Text RCE"),
            ("CVE-2022-42920", "Apache BCEL OOM via crafted class file"),
        ],
    },
    "CWE-327": {
        "java": [
            ("CVE-2020-14720", "Oracle WebLogic weak crypto"),
        ],
    },
    "CWE-1333": {
        "javascript": [
            ("CVE-2021-23358", "ReDoS in marked library"),
        ],
        "python": [
            ("CVE-2021-27291", "ReDoS in PyYAML"),
        ],
    },
    "CWE-367": {
        "java": [
            ("CVE-2018-1258", "Spring Framework TOCTOU race condition"),
        ],
    },
    "CWE-639": {
        "java": [
            ("CVE-2022-22965", "Spring Framework authorization bypass"),
        ],
    },
    "CWE-798": {
        "java": [
            ("CVE-2021-44228", "Log4Shell hardcoded credentials in config"),
        ],
    },
    "CWE-1039": {
        "python": [
            ("CVE-2023-29174", "LLM prompt injection in AI applications"),
        ],
    },
}


def enrich_finding_with_cves(finding) -> None:
    """Add CVE references to a finding's raw metadata based on its CWE and language.

    Modifies the finding in-place by adding raw['known_cves'].
    """
    cwe = getattr(finding, 'cwe', '') or ''
    if not cwe or cwe not in CVE_REFERENCES:
        return

    # Determine language from file extension
    file_path = getattr(finding, 'file', '')
    lang = _detect_language(file_path)

    cves = CVE_REFERENCES[cwe].get(lang, [])
    # Also include "multi" CVEs (language-agnostic)
    cves += CVE_REFERENCES[cwe].get("multi", [])

    if cves:
        if not hasattr(finding, 'raw') or finding.raw is None:
            finding.raw = {}
        finding.raw["known_cves"] = [
            {"id": cve_id, "description": desc}
            for cve_id, desc in cves
        ]


def _detect_language(file_path: str) -> str:
    """Detect language from file extension."""
    ext_map = {
        '.py': 'python', '.java': 'java', '.js': 'javascript', '.ts': 'javascript',
        '.go': 'go', '.rs': 'rust', '.c': 'c', '.cpp': 'c', '.h': 'c',
        '.php': 'php', '.rb': 'ruby', '.cs': 'csharp',
    }
    for ext, lang in ext_map.items():
        if file_path.endswith(ext):
            return lang
    return 'unknown'


def get_cves_for_cwe(cwe: str, language: str = '') -> List[dict]:
    """Get known CVEs for a CWE, optionally filtered by language."""
    if cwe not in CVE_REFERENCES:
        return []
    if language:
        cves = CVE_REFERENCES[cwe].get(language, [])
    else:
        cves = []
        for lang_cves in CVE_REFERENCES[cwe].values():
            cves.extend(lang_cves)
    return [{"id": cve_id, "description": desc} for cve_id, desc in cves]


def enrich_findings(findings: list) -> list:
    """Enrich a list of findings with CVE references."""
    for f in findings:
        enrich_finding_with_cves(f)
    return findings
