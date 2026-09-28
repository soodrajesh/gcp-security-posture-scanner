# 0003 — Two seeded misconfigurations are impossible here; their rules are unit-tested instead

**Status:** accepted (found by the first live deploy)

## Context
The lab (`terraform/victims.tf`) creates deliberately bad resources so the scanner has something real to find.
The first apply failed on two of them:

* `constraints/storage.uniformBucketLevelAccess` is enforced by the organization, so a bucket with UBLA off
  cannot be created (HTTP 412).
* `constraints/iam.disableServiceAccountKeyCreation` is enforced, so no user-managed key can be created (HTTP 400).

## Decision
Don't fight the organization. Seed misconfigurations the org allows instead (public bucket binding, BigQuery
dataset shared with `allAuthenticatedUsers`, public Cloud Run service, `roles/editor` on a service account,
world-open firewall rules in an empty VPC). Rules `GCP-STO-001`, `GCP-IAM-001` and `GCP-IAM-002` stay in the rule
set — a scanner should still flag those in projects that lack the guardrail — and are covered by Rego unit tests,
not live findings. `GCP-CE-001/002` (VM rules) are also unit-test-only: a VM is not free and adds nothing the
firewall/IAM checks don't already prove.

## Consequences
* The test suite says plainly which rules are proven live and which only in unit tests (README table).
* "This organization prevents these" is itself useful posture information, and the reason the live run has no
  `GCP-IAM-001` finding.
