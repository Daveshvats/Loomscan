"""IaC scanner — Terraform, Dockerfile, Kubernetes, CloudFormation, Helm, Pulumi."""
from __future__ import annotations
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List

@dataclass
class IaCFinding:
    file: str; line: int; rule_id: str; severity: str; description: str; fix: str; cwe: str = "CWE-732"; confidence: float = 0.85

TERRAFORM_RULES = [
    ("TF-AWS-S3-PUBLIC-ACL", r'resource\s+"aws_s3_bucket"\s+[\s\S]*?acl\s*=\s*"public-read', "critical", "S3 public-read ACL", "Set acl=private"),
    ("TF-AWS-SG-WILDCARD-CIDR", r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]', "high", "SG allows 0.0.0.0/0", "Restrict CIDR"),
    ("TF-AWS-IAM-WILDCARD-ACTION", r'action\s*=\s*\["\*"\]', "critical", "IAM wildcard action", "Scope actions"),
    ("TF-AWS-RDS-PUBLIC", r'publicly_accessible\s*=\s*true', "critical", "RDS publicly accessible", "Set false"),
    ("TF-AZURE-STORAGE-NO-HTTPS", r'enable_https_traffic_only\s*=\s*false', "high", "Azure storage allows HTTP", "Set true"),
    ("TF-GCP-STORAGE-PUBLIC", r'members\s*=\s*\["allUsers"\]', "critical", "GCP bucket public", "Remove allUsers"),
]

DOCKERFILE_RULES = [
    ("DOCKER-ROOT-USER", r'^\s*USER\s+root\b', "high", "Container runs as root", "Use non-root user"),
    ("DOCKER-SECRET-ENV", r'^\s*ENV\s+\w*(?:PASSWORD|SECRET|KEY|TOKEN)\w*\s*=', "critical", "Secret in ENV", "Pass at runtime"),
    ("DOCKER-ADD-URL", r'^\s*ADD\s+https?://', "medium", "ADD with remote URL", "Use curl+COPY"),
    ("DOCKER-APT-NO-CLEAN", r'^\s*RUN\s+apt-get\s+install(?!.*rm\s+-rf\s+/var/lib/apt)', "low", "apt-get without cleanup", "Add rm -rf"),
    ("DOCKER-NO-PIN-VERSION", r'^\s*FROM\s+\w+:\s*latest\b', "medium", "FROM :latest", "Pin version"),
]

K8S_RULES = [
    ("K8S-PRIVILEGED-CONTAINER", r"privileged:\s*true", "critical", "Privileged container", "Set privileged: false"),
    ("K8S-RUN-AS-ROOT", r"runAsUser:\s*0\b", "high", "Runs as root (UID 0)", "Use non-zero UID"),
    ("K8S-HOST-PATH", r"hostPath:\s*", "high", "hostPath mount", "Use emptyDir/PVC"),
    ("K8S-HOST-NETWORK", r"hostNetwork:\s*true", "high", "hostNetwork", "Set false"),
    ("K8S-HOST-PID", r"hostPID:\s*true", "high", "hostPID", "Set false"),
    ("K8S-IMAGE-LATEST", r"image:\s*\w+:latest\b", "medium", ":latest tag", "Pin version"),
]

CLOUDFORMATION_RULES = [
    ("CFN-S3-PUBLIC-READ", r'"(?:AccessControl|ACL)"\s*:\s*"PublicRead', "critical", "S3 PublicRead ACL", "Set to Private"),
    ("CFN-SG-WILDCARD-CIDR", r'"CidrIp"\s*:\s*"0\.0\.0\.0/0"', "high", "SG 0.0.0.0/0", "Restrict"),
    ("CFN-IAM-WILDCARD-ACTION", r'"Action"\s*:\s*"\*"', "critical", "IAM wildcard", "Scope actions"),
    ("CFN-DB-PUBLIC", r'"PubliclyAccessible"\s*:\s*true', "critical", "RDS public", "Set false"),
]

def scan_terraform(file_path, repo_root=None):
    if not file_path.exists() or file_path.suffix != ".tf": return []
    rel = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    try: source = file_path.read_text(encoding="utf-8")
    except: return []
    findings = []
    for rule_id, pattern, severity, desc, fix in TERRAFORM_RULES:
        for m in re.finditer(pattern, source, re.MULTILINE):
            findings.append(IaCFinding(file=rel, line=source[:m.start()].count("\n")+1, rule_id=f"L0.iac.{rule_id}", severity=severity, description=desc, fix=fix))
    return findings

def scan_dockerfile(file_path, repo_root=None):
    if not file_path.exists() or not file_path.name.lower().startswith("dockerfile"): return []
    rel = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    try: source = file_path.read_text(encoding="utf-8")
    except: return []
    findings = []
    lines = source.splitlines()
    for rule_id, pattern, severity, desc, fix in DOCKERFILE_RULES:
        if rule_id == "DOCKER-NO-HEALTHCHECK":
            if not any(re.match(r'^\s*HEALTHCHECK\b', l, re.IGNORECASE) for l in lines):
                findings.append(IaCFinding(file=rel, line=1, rule_id=f"L0.iac.{rule_id}", severity="medium", description="No HEALTHCHECK", fix="Add HEALTHCHECK"))
            continue
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(IaCFinding(file=rel, line=i, rule_id=f"L0.iac.{rule_id}", severity=severity, description=desc, fix=fix))
    return findings

def scan_kubernetes(file_path, repo_root=None):
    if not file_path.exists() or file_path.suffix.lower() not in (".yaml",".yml"): return []
    try: source = file_path.read_text(encoding="utf-8")
    except: return []
    if "apiVersion:" not in source or "kind:" not in source: return []
    rel = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    findings = []
    lines = source.splitlines()
    for rule_id, pattern, severity, desc, fix in K8S_RULES:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line):
                findings.append(IaCFinding(file=rel, line=i, rule_id=f"L0.iac.{rule_id}", severity=severity, description=desc, fix=fix))
    return findings

def scan_cloudformation(file_path, repo_root=None):
    if not file_path.exists() or file_path.suffix.lower() not in (".json",".yaml",".yml"): return []
    try: source = file_path.read_text(encoding="utf-8")
    except: return []
    if "AWSTemplateFormatVersion" not in source and "Resources" not in source: return []
    rel = str(file_path.relative_to(repo_root)) if repo_root else str(file_path)
    findings = []
    for rule_id, pattern, severity, desc, fix in CLOUDFORMATION_RULES:
        for m in re.finditer(pattern, source, re.MULTILINE):
            findings.append(IaCFinding(file=rel, line=source[:m.start()].count("\n")+1, rule_id=f"L0.iac.{rule_id}", severity=severity, description=desc, fix=fix))
    return findings

def scan_iac(repo_root, max_files=100):
    findings = []
    skip_dirs = {".git","__pycache__",".venv","venv","node_modules",".stca-cache","build","dist"}
    count = 0
    for p in repo_root.rglob("*"):
        if not p.is_file() or any(part in skip_dirs for part in p.parts): continue
        name = p.name.lower()
        if p.suffix == ".tf": findings += scan_terraform(p, repo_root)
        elif name.startswith("dockerfile"): findings += scan_dockerfile(p, repo_root)
        elif p.suffix in (".yaml",".yml"): findings += scan_kubernetes(p, repo_root); findings += scan_cloudformation(p, repo_root)
        elif p.suffix == ".json": findings += scan_cloudformation(p, repo_root)
        count += 1
        if count >= max_files: break
    return findings
