# 1. Build and tear down

```bash
gcloud config set project <your-project>     # billing linked; everything else is auto-detected
./scripts/up.sh                              # ~15 min including the live tests and the lifecycle drill
./scripts/up.sh --no-seed --skip-tests       # scanner only, no lab misconfigurations, no tests
./scripts/down.sh                            # destroy everything incl. the lab resources
./scripts/down.sh --purge                    # also drop this repo's Terraform state
```

`up.sh` runs: state bucket → Terraform phase 1 (dataset, views, IAM, alerts, registry, lab) → Cloud Build image → Terraform phase 2 (job, dashboard, scheduler) → first scan → Checkov ingest → `test.sh`.

Prerequisites: `gcloud`, `terraform`, `bq`, `python3`, `curl`, `jq`. `opa` is only needed to run the Rego tests locally (`brew install opa`).

Expected cost: under €1 for a full build-test-drill-destroy cycle. The job and dashboard scale to zero; BigQuery, Pub/Sub and Cloud Asset reads are far below free-tier limits.

Organization policies apply: this repo's first run hit `storage.uniformBucketLevelAccess` and `iam.disableServiceAccountKeyCreation` ([ADR 0003](../adr/0003-org-guardrails-and-unit-tested-rules.md)).
