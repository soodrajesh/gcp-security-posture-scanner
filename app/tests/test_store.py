from unittest import mock

from scanner.store import Store


def test_duplicate_fingerprints_are_collapsed_before_staging():
    bq = mock.MagicMock()
    bq.query.return_value.result.return_value = []
    store = Store("p", "posture", client=bq)
    rows = [
        {"finding_id": "a", "severity": "HIGH"},
        {"finding_id": "a", "severity": "HIGH"},
        {"finding_id": "b", "severity": "LOW"},
    ]
    summary = store.merge_findings(rows, "checkov", "s1", "2026-09-28T00:00:00Z")
    staged = bq.load_table_from_json.call_args.args[0]
    assert sorted(r["finding_id"] for r in staged) == ["a", "b"]
    assert summary["findings_total"] == 2
