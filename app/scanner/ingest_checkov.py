"""Second finding source: turn a Checkov JSON report into the same finding schema and merge it.

    checkov -d terraform --framework terraform -o json > checkov.json
    python -m scanner.ingest_checkov checkov.json

Runs from an operator machine or CI (not the Cloud Run Job): IaC scanning happens where the
code is, before anything is deployed.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timezone

from scanner import findings
from scanner.store import Store


def parse_reports(text: str) -> list[dict]:
    """Checkov prints one JSON document per scanned directory (-d given twice = two documents
    back to back, which json.load rejects as 'Extra data'), and a list when several frameworks ran."""
    decoder, pos, reports = json.JSONDecoder(), 0, []
    while pos < len(text):
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text):
            break
        doc, pos = decoder.raw_decode(text, pos)
        reports.extend(doc if isinstance(doc, list) else [doc])
    return reports


def load_failed_checks(path: str) -> list[dict]:
    with open(path) as fh:
        reports = parse_reports(fh.read())
    return [c for r in reports for c in r.get("results", {}).get("failed_checks", [])]


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python -m scanner.ingest_checkov <checkov.json>", file=sys.stderr)
        return 2
    project = os.environ["PROJECT_ID"]
    scan_id, scan_time = (
        uuid.uuid4().hex[:12],
        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    rows = [findings.normalise_checkov(c, project, scan_id, scan_time) for c in load_failed_checks(argv[1])]
    store = Store(project, os.environ.get("DATASET", "posture"))
    summary = store.merge_findings(rows, "checkov", scan_id, scan_time)
    store.record_scan(scan_id, scan_time, "checkov", len(rows), summary)
    print(json.dumps({k: summary[k] for k in ("findings_total", "opened", "resolved", "by_severity")}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
