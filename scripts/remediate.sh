#!/usr/bin/env bash
# Flip the lab resources between their vulnerable and hardened versions, re-scan, and show
# what the scanner did with the findings. This is the lifecycle drill.
#   ./scripts/remediate.sh hardened     # fix them: their findings must become 'resolved'
#   ./scripts/remediate.sh vulnerable   # regress them: the same findings must REOPEN
source "$(dirname "$0")/lib.sh"
MODE="${1:?usage: remediate.sh hardened|vulnerable}"
case "$MODE" in hardened|vulnerable) ;; *) die "mode must be hardened or vulnerable";; esac
tf_init
export TF_VAR_seed_mode="$MODE"
log "Applying lab resources in '$MODE' mode"
tf_apply >/dev/null
# A single apply is not always enough: the first live drill left 0.0.0.0/0 on a firewall rule that
# had just been "hardened" (both ranges present in Compute Engine itself; only a second apply
# removed it). So converge: re-apply until Terraform reports no remaining diff.
for attempt in 1 2 3; do
  if $TF plan -input=false -detailed-exitcode >/dev/null 2>&1; then ok "converged (no remaining diff)"; break; fi
  warn "attempt $attempt: infrastructure has not converged, applying again"; tf_apply >/dev/null
done
$TF plan -input=false -detailed-exitcode >/dev/null 2>&1 || die "lab resources did not converge to '$MODE'"
# ...and wait until the inventory itself reflects the change before scanning.
world_open() { gcloud asset list --project "$PROJECT_ID" --content-type=resource --asset-types=compute.googleapis.com/Firewall --format=json 2>/dev/null \
  | jq -e '[.[]|select(.name|endswith("/seed-allow-ssh"))|.resource.data.sourceRanges[]]|index("0.0.0.0/0")!=null' >/dev/null; }
WANT=$([ "$MODE" = vulnerable ] && echo 1 || echo 0)
END=$(( $(date +%s) + 240 ))
while :; do
  if world_open; then NOW=1; else NOW=0; fi
  [ "$NOW" = "$WANT" ] && break
  [ "$(date +%s)" -lt "$END" ] || die "the inventory never reflected the '$MODE' state"
  sleep 8
done
ok "inventory reflects the '$MODE' state"
log "Re-scanning"
run_scan >/dev/null
bq --project_id "$PROJECT_ID" query --nouse_legacy_sql --quiet --format=pretty \
  "SELECT FORMAT_TIMESTAMP('%H:%M:%S', scan_time) AS scan_at, findings_total, opened, resolved FROM \`$PROJECT_ID.$DATASET.scans\` WHERE source='cai-rego' ORDER BY scan_time DESC LIMIT 1"
