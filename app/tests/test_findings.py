import json

from scanner import findings

RULES = {
    "GCP-NET-001": {
        "title": "t",
        "severity": "HIGH",
        "frameworks": ["CIS GCP 3.6"],
        "remediation": "fix it",
    }
}
RAW = {
    "rule_id": "GCP-NET-001",
    "resource": "//c/fw/ssh",
    "resource_type": "compute.googleapis.com/Firewall",
    "subject": "port 22",
    "evidence": "e",
}


def row(**over):
    return findings.normalise_rego({**RAW, **over}, RULES, "p", "scan1", "2026-09-28T00:00:00Z")


def test_fingerprint_is_stable_across_scans():
    a = findings.normalise_rego(RAW, RULES, "p", "scan1", "2026-09-28T00:00:00Z")
    b = findings.normalise_rego(RAW, RULES, "p", "scan2", "2026-09-29T00:00:00Z")
    assert a["finding_id"] == b["finding_id"]


def test_fingerprint_distinguishes_subject_and_source():
    assert row(subject="port 22")["finding_id"] != row(subject="port 3389")["finding_id"]
    assert findings.fingerprint("cai-rego", "R", "res") != findings.fingerprint("checkov", "R", "res")


def test_fingerprint_has_no_delimiter_collisions():
    assert findings.fingerprint("a", "bc", "d") != findings.fingerprint("ab", "c", "d")


def test_rego_row_shape_and_rank():
    r = row()
    assert r["status"] == "open" and r["severity_rank"] == 3 and r["resolved_at"] is None
    assert r["first_seen"] == r["last_seen"] == "2026-09-28T00:00:00Z"
    json.dumps(r)  # must be JSON-serialisable for the BigQuery load


def test_checkov_severity_falls_back_by_check_then_default():
    base = {
        "check_id": "CKV_GCP_28",
        "check_name": "n",
        "file_path": "/main.tf",
        "resource": "google_storage_bucket.b",
        "file_line_range": [3, 9],
    }
    assert findings.normalise_checkov(base, "p", "s", "2026-09-28T00:00:00Z")["severity"] == "CRITICAL"
    unknown = findings.normalise_checkov({**base, "check_id": "CKV_GCP_999"}, "p", "s", "2026-09-28T00:00:00Z")
    assert unknown["severity"] == "MEDIUM"
    explicit = findings.normalise_checkov({**base, "severity": "low"}, "p", "s", "2026-09-28T00:00:00Z")
    assert explicit["severity"] == "LOW"


def test_checkov_resource_is_file_and_address():
    base = {
        "check_id": "CKV_GCP_29",
        "check_name": "n",
        "file_path": "/victims.tf",
        "resource": "google_storage_bucket.seed",
        "file_line_range": [1, 5],
    }
    r = findings.normalise_checkov(base, "p", "s", "2026-09-28T00:00:00Z")
    assert r["resource"] == "victims.tf:google_storage_bucket.seed" and r["source"] == "checkov"


def test_checkov_prefers_repo_relative_path_so_scan_roots_do_not_fork_findings():
    base = {
        "check_id": "CKV_GCP_2",
        "check_name": "n",
        "resource": "google_compute_firewall.x",
        "file_line_range": [1, 2],
    }
    a = findings.normalise_checkov(
        {**base, "file_path": "/bad.tf", "repo_file_path": "/iac-samples/bad.tf"},
        "p",
        "s",
        "2026-09-28T00:00:00Z",
    )
    b = findings.normalise_checkov(
        {
            **base,
            "file_path": "/../iac-samples/bad.tf",
            "repo_file_path": "/iac-samples/bad.tf",
        },
        "p",
        "s",
        "2026-09-28T00:00:00Z",
    )
    assert a["finding_id"] == b["finding_id"] and a["resource"] == "iac-samples/bad.tf:google_compute_firewall.x"
