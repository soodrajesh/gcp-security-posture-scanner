# 0002 — Read the Asset API directly; keep the snapshot in BigQuery as a by-product

**Status:** accepted

## Context
Cloud Asset Inventory can export to BigQuery (`gcloud asset export --bigquery-table`), which is a long-running
operation writing a table in the API's own schema. The rules need a specific, stable JSON shape.

## Decision
`app/scanner/inventory.py` calls `ListAssets` for the asset types the rules read (RESOURCE and IAM_POLICY
content types) and hands that JSON to OPA. The same snapshot is then loaded into `posture.assets` (one row per
asset, `body` as a BigQuery JSON column, 30-day partition expiry).

## Consequences
* The input the rules see is exactly what `gcloud asset list` prints, so unit-test fixtures can be captured with
  one command (the `inventory_sample.json` fixture was).
* No long-running export operation to poll, no dataset-schema coupling.
* Only the asset types in `RESOURCE_TYPES`/`IAM_TYPES` are scanned. Adding a rule for a new type means adding it
  there too — a rule for an unlisted type silently never fires (the `every_rule_has_an_asset_type` reasoning is
  in `docs/runbooks/04-add-a-rule.md`).
* Scope is one project. Folder/organization scanning is a change of `parent` plus permissions, not of design.
