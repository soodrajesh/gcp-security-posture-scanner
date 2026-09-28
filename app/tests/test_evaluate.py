"""Runs the real opa binary and the real Rego bundle against a fixture derived from a real
inventory capture (sanitised: project id and numbers replaced with placeholders)."""

import json
import pathlib
import shutil

import pytest
from scanner import evaluate

pytestmark = pytest.mark.skipif(shutil.which("opa") is None, reason="opa binary not installed")
ROOT = pathlib.Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def policies(monkeypatch):
    monkeypatch.setattr(evaluate, "POLICY_DIR", str(ROOT / "policies"))


def test_rules_metadata_loads():
    rules = evaluate.rules()
    assert rules["GCP-NET-001"]["severity"] == "HIGH" and len(rules) >= 15


def test_real_inventory_fixture_yields_expected_rule_ids():
    doc = json.loads((pathlib.Path(__file__).parent / "fixtures" / "inventory_sample.json").read_text())
    found = evaluate.findings(doc)
    ids = sorted({f["rule_id"] for f in found})
    assert ids == [
        "GCP-IAM-003",
        "GCP-IAM-004",
        "GCP-LOG-001",
        "GCP-NET-001",
        "GCP-NET-003",
        "GCP-STO-003",
    ]
    stale = [f for f in found if f["rule_id"] == "GCP-IAM-004"]
    assert len(stale) == len({f["subject"] for f in stale}), "one finding per (role, principal), not per uid"


def test_empty_inventory_is_defined_but_empty():
    assert evaluate.findings({"scan_time": "2026-09-28T00:00:00Z", "resources": [], "iam": []}) == []
