# 5. Troubleshooting — problems actually hit while building this

| Symptom | Cause | Fix |
|---|---|---|
| `terraform apply`: HTTP 412 `storage.uniformBucketLevelAccess` / HTTP 400 "Key creation is not allowed" | Organization policy | Don't seed those; see [ADR 0003](../adr/0003-org-guardrails-and-unit-tested-rules.md) |
| A BigQuery rule never fires | Dataset ACL is only in the IAM_POLICY asset view | Read `iam`, not `resources`, for datasets |
| `Extra data: line N` from the Checkov ingest | One JSON document per `-d` directory | Fixed: `parse_reports` stream-decodes |
| `JSON_VALUE(body, ...)` is NULL | Body stored as a JSON *string* | Fixed: object is loaded directly |
| `Unexpected keyword AT` in `remediate.sh` | Reserved word used as a column alias | Renamed `scan_at` |
| Hardened lab still shows an open finding | The apply did not converge (0.0.0.0/0 left on the firewall) | `remediate.sh` re-applies until no diff |
| `source scripts/lib.sh` fails with `BASH_SOURCE[0]: parameter not set` | The tool shell is zsh | Run scripts as `./scripts/x.sh` (bash), never `source` from zsh |
| No scan results yet after `up.sh` | First execution still running | `gcloud run jobs executions list --job posture-scanner --region europe-west1` |
