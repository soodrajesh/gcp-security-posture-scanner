# Live test results

Captured output of `./scripts/test.sh` against the deployed scanner in project `claude-code-507112` (europe-west1) on 2026-09-28: **45 passed, 0 failed** (the same 45/45 was reproduced on a second run after the final image rebuild). Nothing below is edited except stripping colour codes.

```
==> 1. Infrastructure
✔ dataset posture exists with findings, scans, assets tables and 3 views
✔ scheduler job exists and is ENABLED
==> 2. The dashboard is private
✔ no allUsers / allAuthenticatedUsers binding on the dashboard
✔ unauthenticated request is rejected (HTTP 403)
✔ authenticated request is served (HTTP 200)
==> 3. Inventory and evaluation
✔ a cai-rego scan is recorded with assets scanned > 0
✔ raw inventory snapshot is queryable (JSON body column)
✔ findings carry stable 16-hex fingerprints
==> 4. The lab misconfigurations are caught (severity comes from the rule, not the test)
✔ GCP-NET-001 (HIGH) on seed-allow-ssh
✔ GCP-NET-002 (CRITICAL) on seed-allow-all
✔ GCP-STO-003 (public access prevention not enforced) on lab bucket
✔ GCP-STO-002 (CRITICAL, public) on lab bucket
✔ GCP-BQ-001 (CRITICAL) on the lab dataset shared with allAuthenticatedUsers
✔ GCP-RUN-001 on the public lab Cloud Run service
✔ GCP-IAM-003 (editor on a SA) names seed-lab-runner
✔ severity is mapped: GCP-STO-002 is CRITICAL, GCP-NET-001 is HIGH
✔ framework mapping present (CIS GCP 3.6 on a NET-001 finding)
✔ the scanner also reports the project's own pre-existing posture (default network)
==> 5. Second source: Checkov on IaC (shift-left)
✔ checkov findings exist for the un-deployed pull-request sample
✔ both sources share one schema (cai-rego and checkov in the same table)
✔ checkov and cai-rego findings never collide on finding_id
==> 6. Alerts
✔ Pub/Sub received urgent-finding messages
✔ every message is HIGH or CRITICAL (nothing lower is paged)
✔ a message carries the remediation text
✔ the alert log line exists (what the log-based metric counts)
==> 7. Idempotency: an unchanged environment produces no churn
✔ second scan opened 0 and resolved 0
✔ open-finding count and earliest first_seen are unchanged
✔ no duplicate open findings
==> 8. Least privilege
✔ scanner holds only cloudasset.viewer + bigquery.jobUser + logging.logWriter at project level (got: roles/bigquery.jobUser,roles/cloudasset.viewer,roles/logging.logWriter)
✔ dashboard SA holds only bigquery.jobUser + logging.logWriter at project level (got: roles/bigquery.jobUser,roles/logging.logWriter)
✔ the scanner's own service accounts have NO user-managed keys
==> 9. Dashboard content
✔ dashboard renders the CRITICAL lab finding
✔ JSON API returns open findings
==> 10. Lifecycle drill: harden the lab -> findings resolve; regress it -> findings reopen
✔ converged (no remaining diff)
✔ inventory reflects the 'hardened' state
✔ lab firewall SSH finding RESOLVED (not deleted)
✔ lab allow-all firewall finding RESOLVED
✔ lab bucket public finding RESOLVED
✔ lab bucket PAP finding RESOLVED
✔ lab BigQuery public-access finding RESOLVED
✔ lab Cloud Run public-invoker finding RESOLVED
✔ lab editor-role finding RESOLVED
✔ hardened lab resources produce NO open findings (SSH rule now IAP-only)
✔ unrelated pre-existing findings were NOT resolved by the drill
✔ converged (no remaining diff)
✔ inventory reflects the 'vulnerable' state
✔ regression REOPENS the same finding (same fingerprint, not a new row)
✔ reopened finding kept its original first_seen (earlier than the reopen scan)
✔ still exactly one row per fingerprint after the round trip
45 passed, 0 failed
```

## What the first runs got wrong

This suite passed only after live runs exposed real defects. They are kept here because they are the most useful evidence that the checks are not vacuous:

| # | Found by | Defect | Fix |
|---|---|---|---|
| 1 | first `up.sh` | seeded a bucket with UBLA off and an SA key; the organization forbids both (HTTP 412 / 400) | seeded different misconfigurations; those two rules are unit-tested only ([ADR 0003](adr/0003-org-guardrails-and-unit-tested-rules.md)) |
| 2 | first scan | `GCP-BQ-001` never fired: the dataset ACL is **not** in the RESOURCE view of a BigQuery dataset (my unit-test fixture used an assumed shape) | rule reads the IAM_POLICY view; fixture re-captured live |
| 3 | Checkov ingest | Checkov prints one JSON document per `-d` directory; `json.load` failed with "Extra data" | stream-decode all documents; unit test |
| 4 | "no duplicate open findings" | Checkov reports the same file under different relative paths, and `MERGE` inserts duplicate *source* rows twice | prefer `repo_file_path`; de-duplicate by fingerprint before staging; two unit tests |
| 5 | "raw inventory snapshot is queryable" | `json.dumps` into a BigQuery JSON column stored a JSON *string*, so `JSON_VALUE(body, ...)` returned NULL | pass the object, not a string |
| 6 | lifecycle drill | `at` is a reserved word in BigQuery SQL | renamed alias |
| 7 | lifecycle drill | after the "hardening" apply, Compute Engine still had `0.0.0.0/0` on the rule (both ranges present) and only a second apply removed it; the scanner correctly kept the finding open | `remediate.sh` re-applies until Terraform reports no diff, then waits for the inventory to agree |
