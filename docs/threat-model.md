# Threat model

## What is protected
* **The findings themselves.** A list of every weakness in a project is a target list; it must not be readable by the internet or editable by a workload the scanner watches.
* **The project.** The scanner reads the whole project's configuration; it must not become a way to change it.

## Trust boundaries and controls
| Threat | Control | Where it is proven |
|---|---|---|
| Scanner compromised (bug, poisoned dependency) tries to change the project | Service account holds only `roles/cloudasset.viewer` + `bigquery.jobUser` + `logging.logWriter` at project level; dataset-scoped `dataEditor`; topic-scoped `publisher`. No write role on anything it scans. No key exists. | test §8 |
| Dashboard exposed to the internet | Cloud Run service has no `allUsers`/`allAuthenticatedUsers` binding; reached with `gcloud run services proxy` (your own token). Its SA can only `SELECT` the dataset. | test §2 (403 unauthenticated, 200 authenticated, no public binding) |
| Findings tampered with by another workload | Only the scanner SA and the operator have write access to the dataset; the dashboard SA is read-only. | Terraform `identities.tf` |
| Alert flood hides a real finding | Only *newly opened or reopened* HIGH/CRITICAL findings alert; a steady state is silent (`opened=0` on an unchanged environment). | test §7 |
| A scan silently stops | Job failure alert policy; daily schedule; `scan_history` shows the last run. | `monitoring.tf` |
| Rule set quietly rots (asset shape changes) | Fixtures captured from real inventory; rules for shapes not captured live are labelled as such. Bug #2 in [test results](test-results.md) is exactly this failure, found and fixed. | `opa test`, `pytest` |
| Someone edits a rule to hide a finding | Rules are one reviewable file; CI runs `opa test`; the CIS mapping and severity live beside the logic. | `.github/workflows/ci.yml` |

## Blind spots (deliberate, stated)
* **Scope is one project**, and only the 8 resource types + 4 IAM-policy types in `inventory.py`. Anything else is invisible, not "clean".
* **No runtime detection.** This is configuration posture, not threat detection: it will not see a compromised VM.
* **Inventory is eventually consistent.** A change can take a short while to appear; the daily cadence makes this irrelevant, the drill script waits explicitly.
* **The lab creates real (harmless) misconfigurations in the project** — a public empty bucket, a world-open firewall in an empty VPC, a public hello-world service. They are removed by `down.sh` and can be disabled with `--no-seed`.
* **Severity for Checkov findings is a static map** in `findings.py`, not Checkov's own (its open-source output usually has none).
