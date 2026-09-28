# 0004 — Finding identity is a fingerprint; lifecycle is one MERGE per source

**Status:** accepted

## Decision
`finding_id = sha256(source | rule_id | resource | subject)[:16]`. `subject` disambiguates one resource violating
one rule several ways (two roles on the same project policy). Each scan stages its findings and runs a single
`MERGE` into `posture.findings`:

* fingerprint present in the scan → `open`, `last_seen` refreshed, `first_seen` untouched, `resolved_at` cleared
  (so a regression **reopens the same row**, not a new one);
* fingerprint open in the table but absent from this scan **for the same source and project** → `resolved`.

## Why not "delete and reinsert each scan"
It would lose `first_seen` (time-to-fix, and how long a public bucket was public) and make "what changed since
yesterday" impossible. It would also make every scan look like a fresh alert.

## Consequences
* Sources never resolve each other's findings: a clean Checkov run cannot close a live-cloud finding.
* A resource that is *deleted* resolves its findings (it is absent from the inventory) — correct, but
  indistinguishable from "fixed" in the status column. The evidence text and the `assets` snapshots show which.
* Cloud Asset Inventory is eventually consistent, so a scan started seconds after a change can still see the
  old state; `remediate.sh` waits before scanning, and the daily schedule makes this a non-issue in practice.
