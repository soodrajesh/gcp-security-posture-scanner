# 4. Add a rule

1. **Capture the real shape first.** `gcloud asset list --project P --content-type=resource --asset-types=<type> --format=json` (and again with `--content-type=iam-policy`). Do not write a fixture from the API reference: `GCP-BQ-001` shipped wrong that way (its ACL lives in the IAM_POLICY view, not RESOURCE).
2. Make sure the type is in `RESOURCE_TYPES` / `IAM_TYPES` in `app/scanner/inventory.py`. **A rule for an unlisted type silently never fires.**
3. Add the rule metadata to `rules` in `policies/posture.rego` (id, title, severity, frameworks, remediation) and the `findings contains f if { ... }` body. Include a `subject` when one resource can violate the rule in several ways.
4. Add a positive **and** a negative test in `policies/posture_test.rego`. `opa test policies` must pass.
5. `PYTHONPATH=app .venv/bin/pytest app/tests -q` (the fixture test lists the rule ids expected from the captured inventory).
6. `./scripts/up.sh --skip-tests` rebuilds the image; rescan.
