# 0001 — Rules are Rego, evaluated by the `opa` binary

**Status:** accepted

## Context
The scanner needs a rule set that is reviewable by a security engineer who does not read Python, testable
without a cloud account, and identical in unit tests, CI and the job. Alternatives considered: SQL rules over
the BigQuery inventory, Python functions, and a Rego-to-Python port.

## Decision
All rules live in `policies/posture.rego`; rule metadata (title, severity, framework mapping, remediation)
sits next to the logic in `data.posture.rules`. The job shells out to `opa eval` with the snapshot on stdin.
Python only collects the inventory and normalises the result.

## Consequences
* One source of truth: `opa test policies` (33 unit tests) and the job run the same code.
* Rules are deterministic: they never call `time.now_ns`; the scan time is part of the input, so "key older than
  90 days" is reproducible in a test.
* A subprocess per scan (not per resource) costs ~tens of ms; the whole scan is dominated by the Asset API.
* Rego has a learning curve, and SQL would have let the rules run inside BigQuery. We keep the raw snapshot in
  `posture.assets` so ad-hoc SQL over the same data is still possible.
