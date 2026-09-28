# 3. Triage a finding

An alert email ("Posture: new HIGH/CRITICAL finding") means a scan **opened or reopened** a HIGH/CRITICAL finding.

1. Open the dashboard (runbook 2) or `SELECT * FROM posture.v_open_findings`. The row names the resource, the evidence, the CIS control and the fix.
2. Decide: **fix**, **accept** (there is no suppression mechanism yet — see below), or **false positive** (fix the rule, runbook 4).
3. Fix it in Terraform, apply, then `gcloud run jobs execute posture-scanner --region europe-west1 --wait`. The finding moves to `resolved` with `resolved_at` set; if it comes back it **reopens the same row** and keeps its original `first_seen`.
4. A finding on a resource that was *deleted* also resolves (the resource is gone from the inventory); the `assets` snapshots show which it was.

**Known gap:** there is no accept/suppress workflow. An accepted risk stays open and stays in the dashboard. Adding one means a `suppressions` table joined into `v_open_findings`; deliberately not built.

Worked example from this project's own first scan: `GCP-IAM-004` ×13 — stale bindings for deleted `keda-demo-*` service accounts, including `roles/container.admin` and `roles/iam.serviceAccountAdmin`. Fix: remove the bindings; the 13 findings resolve on the next scan.
