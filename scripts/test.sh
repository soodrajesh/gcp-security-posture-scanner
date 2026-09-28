#!/usr/bin/env bash
# Live test suite against the running scanner. Every negative check is paired with a positive one
# so a check can't pass vacuously (an empty table "has no CRITICALs" too).
#   ./scripts/test.sh              everything, including the remediate/regress lifecycle drill
#   SKIP_DRILL=1 ./scripts/test.sh everything except the drill
source "$(dirname "$0")/lib.sh"
need gcloud; need bq; need curl; need jq
PASS=0; FAIL=0
check() { # <description> <command...>
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then PASS=$((PASS+1)); ok "$desc"; else FAIL=$((FAIL+1)); printf '\033[1;31m✘ %s\033[0m\n' "$desc"; fi
}
eq()  { [ "$1" = "$2" ]; }
contains() { grep -q -- "$2" <<<"$1"; }
ge()  { [ "${1:-0}" -ge "$2" ]; }
q()   { bq_scalar "$1"; }
F="\`$PROJECT_ID.$DATASET.findings\`"
open_count() { q "SELECT COUNT(*) FROM $F WHERE status='open' AND source='cai-rego' AND rule_id='$1' AND resource LIKE '%$2%'"; }
resolved_count() { q "SELECT COUNT(*) FROM $F WHERE status='resolved' AND source='cai-rego' AND rule_id='$1' AND resource LIKE '%$2%'"; }

TF_VAR_image="$(cat "$ROOT/.last-image")"; export TF_VAR_image; tf_init

log "1. Infrastructure"
check "dataset $DATASET exists with findings, scans, assets tables and 3 views" \
  eq "$(q "SELECT COUNT(*) FROM \`$PROJECT_ID.$DATASET.INFORMATION_SCHEMA.TABLES\` WHERE table_name IN ('findings','findings_staging','scans','assets','v_open_findings','v_recently_resolved','v_scan_history')")" 7
check "scheduler job exists and is ENABLED" \
  eq "$(gcloud scheduler jobs describe "$($TF output -raw scheduler_job)" --project "$PROJECT_ID" --location "$REGION" --format='value(state)')" ENABLED

log "2. The dashboard is private"
SVC="$($TF output -raw ui_service)"
URL="$(gcloud run services describe "$SVC" --project "$PROJECT_ID" --region "$REGION" --format='value(status.url)')"
POLICY="$(gcloud run services get-iam-policy "$SVC" --project "$PROJECT_ID" --region "$REGION" --format=json)"
check "no allUsers / allAuthenticatedUsers binding on the dashboard" \
  eq "$(echo "$POLICY" | jq '[.bindings[]?.members[]?|select(.=="allUsers" or .=="allAuthenticatedUsers")]|length')" 0
check "unauthenticated request is rejected (HTTP 403)" \
  eq "$(curl -s -o /dev/null -w '%{http_code}' "$URL/")" 403
TOKEN="$(gcloud auth print-identity-token)"
check "authenticated request is served (HTTP 200)" \
  eq "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$URL/")" 200

log "3. Inventory and evaluation"
check "a cai-rego scan is recorded with assets scanned > 0" \
  ge "$(q "SELECT IFNULL(MAX(assets_scanned),0) FROM \`$PROJECT_ID.$DATASET.scans\` WHERE source='cai-rego'")" 1
check "raw inventory snapshot is queryable (JSON body column)" \
  ge "$(q "SELECT COUNT(*) FROM \`$PROJECT_ID.$DATASET.assets\` WHERE asset_type='compute.googleapis.com/Firewall' AND JSON_VALUE(body,'\$.direction')='INGRESS'")" 1
check "findings carry stable 16-hex fingerprints" \
  eq "$(q "SELECT COUNTIF(NOT REGEXP_CONTAINS(finding_id, r'^[0-9a-f]{16}\$')) FROM $F")" 0

log "4. The lab misconfigurations are caught (severity comes from the rule, not the test)"
check "GCP-NET-001 (HIGH) on seed-allow-ssh"          ge "$(open_count GCP-NET-001 seed-allow-ssh)" 1
check "GCP-NET-002 (CRITICAL) on seed-allow-all"      ge "$(open_count GCP-NET-002 seed-allow-all)" 1
check "GCP-STO-003 (public access prevention not enforced) on lab bucket" ge "$(open_count GCP-STO-003 posture-seed)" 1
check "GCP-STO-002 (CRITICAL, public) on lab bucket"  ge "$(open_count GCP-STO-002 posture-seed)" 1
check "GCP-BQ-001 (CRITICAL) on the lab dataset shared with allAuthenticatedUsers" ge "$(open_count GCP-BQ-001 seed_lab)" 1
check "GCP-RUN-001 on the public lab Cloud Run service" ge "$(open_count GCP-RUN-001 seed-lab-hello)" 1
check "GCP-IAM-003 (editor on a SA) names seed-lab-runner" \
  ge "$(q "SELECT COUNT(*) FROM $F WHERE status='open' AND rule_id='GCP-IAM-003' AND evidence LIKE '%seed-lab-runner%'")" 1
check "severity is mapped: GCP-STO-002 is CRITICAL, GCP-NET-001 is HIGH" \
  eq "$(q "SELECT CONCAT(MAX(IF(rule_id='GCP-STO-002',severity,'')),'/',MAX(IF(rule_id='GCP-NET-001',severity,''))) FROM $F WHERE status='open'")" "CRITICAL/HIGH"
check "framework mapping present (CIS GCP 3.6 on a NET-001 finding)" \
  ge "$(q "SELECT COUNT(*) FROM $F WHERE rule_id='GCP-NET-001' AND 'CIS GCP 3.6' IN UNNEST(frameworks)")" 1
check "the scanner also reports the project's own pre-existing posture (default network)" \
  ge "$(q "SELECT COUNT(*) FROM $F WHERE status='open' AND rule_id='GCP-NET-003'")" 1

log "5. Second source: Checkov on IaC (shift-left)"
check "checkov findings exist for the un-deployed pull-request sample" \
  ge "$(q "SELECT COUNT(*) FROM $F WHERE source='checkov' AND status='open' AND resource LIKE 'iac-samples/bad-change.tf:%'")" 2
check "both sources share one schema (cai-rego and checkov in the same table)" \
  eq "$(q "SELECT COUNT(DISTINCT source) FROM $F WHERE status='open'")" 2
check "checkov and cai-rego findings never collide on finding_id" \
  eq "$(q "SELECT COUNT(*)-COUNT(DISTINCT finding_id) FROM $F")" 0

log "6. Alerts"
SUB="$($TF output -raw verify_subscription)"
MSGS="$(gcloud pubsub subscriptions pull "$SUB" --project "$PROJECT_ID" --limit 100 --auto-ack --format=json 2>/dev/null || echo '[]')"
check "Pub/Sub received urgent-finding messages" ge "$(echo "$MSGS" | jq 'length')" 1
check "every message is HIGH or CRITICAL (nothing lower is paged)" \
  eq "$(echo "$MSGS" | jq '[.[].message.attributes.severity|select(.!="HIGH" and .!="CRITICAL")]|length')" 0
check "a message carries the remediation text" \
  ge "$(echo "$MSGS" | jq '[.[].message.data|@base64d|fromjson|select(.remediation!=null and (.remediation|length)>10)]|length')" 1
check "the alert log line exists (what the log-based metric counts)" \
  ge "$(gcloud logging read 'resource.type="cloud_run_job" AND jsonPayload.alert=true' --project "$PROJECT_ID" --limit 1 --freshness 1d --format='value(jsonPayload.rule_id)' | wc -l | tr -d ' ')" 1

log "7. Idempotency: an unchanged environment produces no churn"
BEFORE="$(q "SELECT CONCAT(COUNT(*),'/',MIN(first_seen)) FROM $F WHERE source='cai-rego' AND status='open'")"
run_scan >/dev/null
check "second scan opened 0 and resolved 0" \
  eq "$(q "SELECT CONCAT(opened,'/',resolved) FROM \`$PROJECT_ID.$DATASET.scans\` WHERE source='cai-rego' ORDER BY scan_time DESC LIMIT 1")" "0/0"
check "open-finding count and earliest first_seen are unchanged" \
  eq "$(q "SELECT CONCAT(COUNT(*),'/',MIN(first_seen)) FROM $F WHERE source='cai-rego' AND status='open'")" "$BEFORE"
check "no duplicate open findings" \
  eq "$(q "SELECT COUNT(*)-COUNT(DISTINCT finding_id) FROM $F WHERE status='open'")" 0

log "8. Least privilege"
ROLES="$(gcloud projects get-iam-policy "$PROJECT_ID" --format=json | jq -r --arg m "serviceAccount:posture-scanner@$PROJECT_ID.iam.gserviceaccount.com" '[.bindings[]|select(.members|index($m))|.role]|sort|join(",")')"
check "scanner holds only cloudasset.viewer + bigquery.jobUser + logging.logWriter at project level (got: $ROLES)" \
  eq "$ROLES" "roles/bigquery.jobUser,roles/cloudasset.viewer,roles/logging.logWriter"
UIROLES="$(gcloud projects get-iam-policy "$PROJECT_ID" --format=json | jq -r --arg m "serviceAccount:posture-ui@$PROJECT_ID.iam.gserviceaccount.com" '[.bindings[]|select(.members|index($m))|.role]|sort|join(",")')"
check "dashboard SA holds only bigquery.jobUser + logging.logWriter at project level (got: $UIROLES)" \
  eq "$UIROLES" "roles/bigquery.jobUser,roles/logging.logWriter"
check "the scanner's own service accounts have NO user-managed keys" \
  eq "$(for s in posture-scanner posture-ui posture-scheduler posture-build; do gcloud iam service-accounts keys list --iam-account "$s@$PROJECT_ID.iam.gserviceaccount.com" --managed-by=user --format='value(name)'; done | wc -l | tr -d ' ')" 0

log "9. Dashboard content"
BODY="$(curl -s -H "Authorization: Bearer $TOKEN" "$URL/")"
check "dashboard renders the CRITICAL lab finding" contains "$BODY" GCP-STO-002
check "JSON API returns open findings" \
  ge "$(curl -s -H "Authorization: Bearer $TOKEN" "$URL/api/findings" | jq 'length')" 5

if [ "${SKIP_DRILL:-0}" != 1 ]; then
  log "10. Lifecycle drill: harden the lab -> findings resolve; regress it -> findings reopen"
  "$ROOT/scripts/remediate.sh" hardened
  check "lab firewall SSH finding RESOLVED (not deleted)"   ge "$(resolved_count GCP-NET-001 seed-allow-ssh)" 1
  check "lab allow-all firewall finding RESOLVED"            ge "$(resolved_count GCP-NET-002 seed-allow-all)" 1
  check "lab bucket public finding RESOLVED"                 ge "$(resolved_count GCP-STO-002 posture-seed)" 1
  check "lab bucket PAP finding RESOLVED"                    ge "$(resolved_count GCP-STO-003 posture-seed)" 1
  check "lab BigQuery public-access finding RESOLVED"        ge "$(resolved_count GCP-BQ-001 seed_lab)" 1
  check "lab Cloud Run public-invoker finding RESOLVED"      ge "$(resolved_count GCP-RUN-001 seed-lab-hello)" 1
  check "lab editor-role finding RESOLVED"                   ge "$(q "SELECT COUNT(*) FROM $F WHERE status='resolved' AND rule_id='GCP-IAM-003' AND evidence LIKE '%seed-lab-runner%'")" 1
  check "hardened lab resources produce NO open findings (SSH rule now IAP-only)" \
    eq "$(q "SELECT COUNT(*) FROM $F WHERE status='open' AND source='cai-rego' AND (resource LIKE '%seed-allow-%' OR resource LIKE '%posture-seed%' OR resource LIKE '%seed_lab%' OR resource LIKE '%seed-lab-hello%' OR evidence LIKE '%seed-lab-runner%')")" 0
  check "unrelated pre-existing findings were NOT resolved by the drill" \
    ge "$(q "SELECT COUNT(*) FROM $F WHERE status='open' AND rule_id='GCP-NET-003'")" 1
  "$ROOT/scripts/remediate.sh" vulnerable
  check "regression REOPENS the same finding (same fingerprint, not a new row)" \
    ge "$(open_count GCP-NET-002 seed-allow-all)" 1
  check "reopened finding kept its original first_seen (earlier than the reopen scan)" \
    ge "$(q "SELECT COUNT(*) FROM $F WHERE rule_id='GCP-NET-002' AND status='open' AND first_seen < (SELECT MAX(scan_time) FROM \`$PROJECT_ID.$DATASET.scans\` WHERE source='cai-rego')")" 1
  check "still exactly one row per fingerprint after the round trip" \
    eq "$(q "SELECT COUNT(*)-COUNT(DISTINCT finding_id) FROM $F")" 0
fi

echo
printf '\033[1m%d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
