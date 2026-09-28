import json

from scanner.ingest_checkov import parse_reports


def doc(*ids):
    return {
        "check_type": "terraform",
        "results": {"failed_checks": [{"check_id": i} for i in ids]},
    }


def test_two_concatenated_documents_are_both_read():
    text = json.dumps(doc("A"), indent=4) + "\n" + json.dumps(doc("B", "C"), indent=4)
    got = parse_reports(text)
    assert [c["check_id"] for r in got for c in r["results"]["failed_checks"]] == [
        "A",
        "B",
        "C",
    ]


def test_single_document_and_list_forms():
    assert len(parse_reports(json.dumps(doc("A")))) == 1
    assert len(parse_reports(json.dumps([doc("A"), doc("B")]))) == 2


def test_empty_output_yields_no_reports():
    assert parse_reports("  \n") == []
