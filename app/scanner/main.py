"""Cloud Run Job entrypoint: inventory -> Rego -> common findings -> BigQuery -> alerts.

Every log line is one JSON object on stdout so Cloud Logging parses it into jsonPayload;
`alert: true` lines are what the log-based metric (terraform/monitoring.tf) counts.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timezone

from scanner import evaluate, findings, inventory
from scanner.store import Store

PROJECT_ID = os.environ["PROJECT_ID"]
DATASET = os.environ.get("DATASET", "posture")
TOPIC_ID = os.environ.get("TOPIC_ID", "")
MAX_ALERTS = int(os.environ.get("MAX_ALERTS", "25"))


def log(**payload) -> None:
    print(json.dumps(payload, default=str), flush=True)


def publish_alerts(newly_open: list[dict]) -> int:
    urgent = [f for f in newly_open if f["severity"] in findings.ALERT_SEVERITIES][:MAX_ALERTS]
    if not urgent:
        return 0
    from google.cloud import (
        pubsub_v1,
    )  # imported lazily: unit tests and dry runs don't need it

    publisher = pubsub_v1.PublisherClient()
    topic = publisher.topic_path(PROJECT_ID, TOPIC_ID)
    for f in urgent:
        body = {
            k: f[k]
            for k in (
                "finding_id",
                "rule_id",
                "title",
                "severity",
                "resource",
                "evidence",
                "remediation",
                "project_id",
            )
        }
        publisher.publish(
            topic,
            json.dumps(body).encode(),
            severity=f["severity"],
            rule_id=f["rule_id"],
        ).result(timeout=30)
        log(
            severity="WARNING",
            event="new_finding",
            alert=True,
            **{k: f[k] for k in ("rule_id", "finding_id", "resource", "evidence")},
            finding_severity=f["severity"],
        )
    return len(urgent)


def main() -> int:
    scan_id = uuid.uuid4().hex[:12]
    scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    log(event="scan_start", scan_id=scan_id, project=PROJECT_ID)

    snapshot = inventory.collect(PROJECT_ID)
    snapshot["scan_time"] = scan_time
    n_assets = len(snapshot["resources"]) + len(snapshot["iam"])

    store = Store(PROJECT_ID, DATASET)
    store.save_inventory(scan_id, scan_time, snapshot)

    rules = evaluate.rules()
    raw = evaluate.findings(snapshot)
    rows = [findings.normalise_rego(r, rules, PROJECT_ID, scan_id, scan_time) for r in raw]

    summary = store.merge_findings(rows, "cai-rego", scan_id, scan_time)
    store.record_scan(scan_id, scan_time, "cai-rego", n_assets, summary)
    alerted = publish_alerts(summary["newly_open"]) if TOPIC_ID else 0

    log(
        event="scan_complete", scan_id=scan_id, assets=n_assets, findings=summary["findings_total"],
        opened=summary["opened"], resolved=summary["resolved"], by_severity=summary["by_severity"], alerts_published=alerted,
    )  # fmt: skip
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # a failed scan must fail the job so the failure alert fires
        log(severity="ERROR", event="scan_failed", error=f"{type(exc).__name__}: {exc}")
        raise
