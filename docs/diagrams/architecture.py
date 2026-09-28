#!/usr/bin/env python3
"""Generates docs/img/architecture.svg (PNG via docs/diagrams/render.py).

    python3 docs/diagrams/architecture.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from archlib import Diagram  # noqa: E402

OUT = os.path.join(os.path.dirname(__file__), "..", "img", "architecture.svg")

W, H = 1780, 1390
d = Diagram(W, H, "Cloud Security Posture Scanner on Google Cloud",
            "Cloud Asset Inventory · OPA/Rego rules · common finding schema in BigQuery · Pub/Sub + log-based alerts · private dashboard · Terraform")

d.group(190, 100, 1480, 710, "Google Cloud project  ·  europe-west1", "#1a73e8", dash=False, fill="#f8faff", label_w=330)

d.node("checkov", 70, 310, "Checkov", "policy", "security", "IaC scan in CI /\noperator machine")
d.node("cai", 330, 310, "Cloud Asset\nInventory", "db", "data", "ListAssets: RESOURCE\n+ IAM_POLICY")
d.node("job", 700, 310, "posture-scanner", "run", "compute", "Cloud Run Job\n(read-only SA)")
d.node("bq", 1000, 310, "BigQuery posture", "db", "data", "assets · findings ·\nscans · 3 views")
d.node("ui", 1280, 310, "posture-ui", "chart", "compute", "Cloud Run service\nno public access")
d.node("user", 1560, 310, "Operator", "user", "actor", "gcloud run services\nproxy (own identity)")
d.node("sched", 430, 190, "Cloud Scheduler", "filter", "ops", "daily cron · OAuth\ntoken, no keys")
d.node("topic", 330, 480, "Pub/Sub", "bolt", "data", "posture-new-findings\n(HIGH / CRITICAL)")
d.node("opa", 1000, 480, "OPA + Rego", "shield", "security", "16 rules · CIS GCP\nmapping · 33 tests")
d.node("logs", 700, 690, "Cloud Logging", "policy", "ops", "JSON lines\nalert=true")
d.node("metric", 1000, 690, "Log-based metric", "chart", "ops", "posture_new_\nurgent_findings")
d.node("alert", 1280, 690, "Alert policy", "bolt", "ops", "> 0 in 24h")
d.node("chan", 1560, 690, "Email channel", "user", "actor", "alert_email")

d.edge("sched", "job", "hv", num=1, label="POST jobs.run", sides=("r", "t"))
d.edge("job", "cai", "h", num=2, label="ListAssets")
d.path([(730, 340), (730, 480), (970, 480)], num=3, label="snapshot on stdin ->\nfindings JSON", lab_at=(850, 468))
d.edge("job", "bq", "h", num=4, label="snapshot + MERGE\nfindings + scan row")
d.path([(670, 340), (670, 480), (360, 480)], num=5, label="new HIGH/CRITICAL", lab_at=(520, 468))
d.edge("job", "logs", "v", num=6, label="stdout JSON")
d.edge("logs", "metric", "h")
d.edge("metric", "alert", "h", num=7)
d.edge("alert", "chan", "h")
d.edge("bq", "ui", "h", num=8, label="SELECT on views")
d.edge("user", "ui", "h", num=9)
d.path([(70, 280), (70, 140), (1000, 140), (1000, 280)], num=10, label="second source: same findings table", lab_at=(560, 128))

d.badge(250, 850, "11", "#1e8e3e")
d.text(270, 855, "The scanner holds only roles/cloudasset.viewer + bigquery.jobUser + logging.logWriter at project level, plus dataset-scoped BigQuery editor and topic-scoped publisher.", 12, "#3c4043")
d.text(270, 873, "The dashboard SA can only SELECT from this dataset. No service-account keys exist (and the organization forbids creating them). Nothing is publicly invokable.", 12, "#3c4043")

d.band(190, 900, 1480, 130, "WHAT IS PROVEN LIVE vs ONLY UNIT-TESTED  ·  see docs/adr/0003", "#d93025", "#fff8f7")
d.text(220, 942, "Live: world-open SSH/RDP + allow-all firewalls, public bucket, BigQuery dataset shared with allAuthenticatedUsers, public Cloud Run service, Editor on a service account,", 12.5, "#3c4043")
d.text(220, 966, "plus the project's own pre-existing gaps (default network, stale IAM bindings, no audit config). Unit-test only: UBLA-off buckets and SA keys (the organization blocks creating them),", 12.5, "#3c4043")
d.text(220, 990, "and VM rules (a VM is not free). The README table says which is which.", 12.5, "#3c4043")

d.legend(34, 1070, "Numbered flows", [
    ("1", "Cloud Scheduler calls the Cloud Run Admin API to start the job with its own service account's OAuth token"),
    ("2", "The job lists assets of 8 types twice: RESOURCE (configuration) and IAM_POLICY (who can do what)"),
    ("3", "The snapshot is piped to `opa eval`; every rule in policies/posture.rego runs; the findings set comes back"),
    ("4", "Findings are normalised to the common schema (stable fingerprint, severity, CIS mapping, remediation) and MERGEd: open / refresh / resolve"),
    ("5", "Newly opened (or reopened) HIGH and CRITICAL findings are published to Pub/Sub with the remediation text"),
    ("6", "The same findings are logged as JSON lines with alert=true"),
    ("7", "A log-based metric counts them; an alert policy emails on any in 24h. A second policy alerts if the job itself fails"),
    ("8", "The dashboard queries only the views v_open_findings, v_recently_resolved, v_scan_history"),
    ("9", "The operator reaches the private service through `gcloud run services proxy`, which attaches their identity token"),
    ("10", "Checkov output for Terraform is normalised into the same schema (source=checkov); sources never resolve each other's findings"),
], w=1720)
d.key(34, 1340)

d.save(OUT)
print("wrote", os.path.abspath(OUT))
