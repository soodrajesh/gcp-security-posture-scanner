#!/usr/bin/env bash
# Delete everything this repo created, end to end.
#   ./scripts/down.sh            destroy the scanner and the lab misconfigurations
#   ./scripts/down.sh --purge    also delete this repo's Terraform state (and the bucket if now empty)
source "$(dirname "$0")/lib.sh"
need gcloud; need terraform
PURGE=0; [ "${1:-}" = "--purge" ] && PURGE=1

log "Project $PROJECT_ID — destroying everything managed by this repo"
tf_init
TF_VAR_image="$(cat "$ROOT/.last-image" 2>/dev/null || echo "")"; export TF_VAR_image
export TF_VAR_seed_mode=vulnerable # so the destroy plan covers the lab resources whatever mode they were last in
log "1/2 Terraform destroy"
$TF destroy -input=false -auto-approve
ok "scanner and lab resources destroyed"
rm -f "$ROOT/.last-image"; rm -rf "$ROOT/.test-tmp"

if [ "$PURGE" = 1 ]; then
  log "2/2 Purging this repo's Terraform state"
  gcloud storage rm -r "gs://$STATE_BUCKET/posture-scanner/" --quiet >/dev/null 2>&1 || true
  if [ -z "$(gcloud storage ls "gs://$STATE_BUCKET/" 2>/dev/null)" ]; then
    gcloud storage rm -r "gs://$STATE_BUCKET" --quiet >/dev/null 2>&1 || true; ok "state prefix and (now empty) bucket removed"
  else ok "state prefix removed; bucket kept because other stacks still use it"; fi
else log "2/2 Kept state bucket gs://$STATE_BUCKET (a few KB; --purge removes it)"; fi

log "Anything left?"
echo "  Cloud Run jobs (posture-scanner):     $(gcloud run jobs list --project "$PROJECT_ID" --region "$REGION" --format='value(name)' 2>/dev/null | grep -c '^posture-scanner$' || true)"
echo "  Cloud Run services (posture-ui):      $(gcloud run services list --project "$PROJECT_ID" --region "$REGION" --format='value(metadata.name)' 2>/dev/null | grep -c '^posture-ui$' || true)"
echo "  Scheduler jobs (posture-daily-scan):  $(gcloud scheduler jobs list --project "$PROJECT_ID" --location "$REGION" --format='value(name)' 2>/dev/null | grep -c 'posture-daily-scan' || true)"
echo "  BigQuery dataset (posture):           $(bq --project_id "$PROJECT_ID" ls -d 2>/dev/null | grep -c ' posture *$' || true)"
echo "  Lab bucket (…-posture-seed):          $(gcloud storage buckets list --project "$PROJECT_ID" --format='value(name)' 2>/dev/null | grep -c 'posture-seed$' || true)"
echo "  Lab firewall rules (seed-*):          $(gcloud compute firewall-rules list --project "$PROJECT_ID" --format='value(name)' 2>/dev/null | grep -c '^seed-' || true)"
echo "  Lab service account (seed-lab-runner): $(gcloud iam service-accounts list --project "$PROJECT_ID" --format='value(email)' 2>/dev/null | grep -c '^seed-lab-runner@' || true)"
log "DONE"
