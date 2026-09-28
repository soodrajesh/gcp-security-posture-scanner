# Architecture

![Architecture](img/architecture.png)

## Data flow of one scan
1. **Cloud Scheduler** (or `./scripts/up.sh`, or a manual `gcloud run jobs execute`) starts the `posture-scanner` Cloud Run Job.
2. The job calls Cloud Asset Inventory `ListAssets` twice per asset-type set: RESOURCE (configuration) and IAM_POLICY (who can do what).
3. The snapshot is stored in `posture.assets` (JSON body, 30-day partition expiry) and piped to `opa eval` with `policies/posture.rego`.
4. Each result is normalised to the **common finding schema** — `finding_id` (stable fingerprint), `source`, `rule_id`, `severity`, `frameworks`, `resource`, `evidence`, `remediation`, `status`, `first_seen`/`last_seen`/`resolved_at`.
5. One `MERGE` per (source, project) opens, refreshes or resolves findings ([ADR 0004](adr/0004-fingerprints-and-merge-lifecycle.md)); a row goes into `posture.scans`.
6. Newly opened HIGH/CRITICAL findings go to Pub/Sub and to Cloud Logging (`alert=true`), where a log-based metric and an alert policy email the operator.
7. The private dashboard reads three views: `v_open_findings`, `v_recently_resolved`, `v_scan_history`.

A second **source** — Checkov over Terraform — is merged into the same table by `scripts/ingest-checkov.sh`, so IaC findings (before deployment) and cloud findings (after) are queried together.

## Tables
| Table / view | Purpose |
|---|---|
| `findings` | every finding ever seen, with lifecycle; clustered by status, severity |
| `findings_staging` | scratch: one scan's findings before the `MERGE` |
| `assets` | raw inventory snapshot per scan |
| `scans` | one row per scan per source: assets scanned, findings, opened, resolved |
| `v_open_findings`, `v_recently_resolved`, `v_scan_history` | what the dashboard reads |
