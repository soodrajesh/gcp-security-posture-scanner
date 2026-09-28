"""The common finding schema. Every source (CAI+Rego, Checkov, ...) is normalised into this
shape before it touches BigQuery, so the store, the alerts and the UI never care where a
finding came from."""

from __future__ import annotations

import hashlib
from typing import Any

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
ALERT_SEVERITIES = {"CRITICAL", "HIGH"}


def fingerprint(source: str, rule_id: str, resource: str, subject: str = "") -> str:
    """Stable identity of a finding across scans. Includes `subject` because one resource
    can violate one rule several ways (e.g. two roles on the same project policy)."""
    raw = "\x1f".join((source, rule_id, resource, subject))
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def normalise_rego(
    raw: dict[str, Any],
    rules: dict[str, Any],
    project_id: str,
    scan_id: str,
    scan_time: str,
) -> dict:
    """One element of data.posture.findings + the rule metadata -> a findings row."""
    meta = rules[raw["rule_id"]]
    return _row(
        source="cai-rego",
        rule_id=raw["rule_id"],
        title=meta["title"],
        severity=meta["severity"],
        frameworks=meta["frameworks"],
        resource=raw["resource"],
        resource_type=raw["resource_type"],
        subject=raw.get("subject", ""),
        evidence=raw["evidence"],
        remediation=meta["remediation"],
        project_id=project_id,
        scan_id=scan_id,
        scan_time=scan_time,
    )


def _row(
    *,
    source,
    rule_id,
    title,
    severity,
    frameworks,
    resource,
    resource_type,
    subject,
    evidence,
    remediation,
    project_id,
    scan_id,
    scan_time,
) -> dict:
    return {
        "finding_id": fingerprint(source, rule_id, resource, subject),
        "source": source,
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "severity_rank": SEVERITY_RANK[severity],
        "frameworks": list(frameworks),
        "resource": resource,
        "resource_type": resource_type,
        "subject": subject,
        "evidence": evidence,
        "remediation": remediation,
        "project_id": project_id,
        "status": "open",
        "first_seen": scan_time,
        "last_seen": scan_time,
        "resolved_at": None,
        "last_scan_id": scan_id,
    }


# Checkov's open-source output usually has severity=null; rank the checks we expect to hit.
CHECKOV_SEVERITY = {
    "CKV_GCP_2": "HIGH",  # firewall allows 22 from 0.0.0.0/0
    "CKV_GCP_3": "HIGH",  # firewall allows 3389 from 0.0.0.0/0
    "CKV_GCP_28": "CRITICAL",  # bucket is public
    "CKV_GCP_29": "MEDIUM",  # bucket lacks uniform bucket-level access
    "CKV_GCP_62": "LOW",  # bucket without access logging
    "CKV_GCP_78": "LOW",  # bucket without versioning
    "CKV_GCP_41": "HIGH",  # SA user role granted at project level
    "CKV_GCP_49": "HIGH",  # roles/editor or owner-like primitive grants to SAs
}


def normalise_checkov(check: dict[str, Any], project_id: str, scan_id: str, scan_time: str) -> dict:
    """One failed Checkov check -> a findings row. The 'resource' is repo-relative
    `file:terraform_address` since IaC has no cloud resource name yet."""
    check_id = check["check_id"]
    severity = (check.get("severity") or CHECKOV_SEVERITY.get(check_id) or "MEDIUM").upper()
    if severity not in SEVERITY_RANK:
        severity = "MEDIUM"
    # `repo_file_path` is repo-relative and stable; `file_path` is relative to whichever -d directory
    # was scanned (and can even read `/../iac-samples/x.tf`), so it would fork one finding into several.
    file_path = (check.get("repo_file_path") or check.get("file_path", "")).lstrip("/")
    resource = f"{file_path}:{check.get('resource', '')}"
    lines = check.get("file_line_range") or []
    return _row(
        source="checkov",
        rule_id=check_id,
        title=check.get("check_name", check_id),
        severity=severity,
        frameworks=["Checkov"],
        resource=resource,
        resource_type="terraform",
        subject="",
        evidence=f"{resource} lines {lines[0]}-{lines[1]}" if len(lines) == 2 else resource,
        remediation=check.get("guideline") or "See the Checkov policy documentation for this check.",
        project_id=project_id,
        scan_id=scan_id,
        scan_time=scan_time,
    )
