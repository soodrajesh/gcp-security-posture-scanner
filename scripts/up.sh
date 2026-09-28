#!/usr/bin/env bash
# Build the whole scanner end to end, then prove it works:
#   state bucket -> dataset/IAM/alerts + lab misconfigurations -> image build -> Cloud Run job,
#   dashboard and scheduler -> first scan -> Checkov ingest of the IaC samples -> live tests.
# Two Terraform phases: the job and dashboard need the image digest, so infra comes first.
#   ./scripts/up.sh [--plan] [--skip-tests] [--no-seed]
source "$(dirname "$0")/lib.sh"
PLAN_ONLY=0; SKIP_TESTS=0; SEED=vulnerable
for a in "$@"; do case "$a" in --plan) PLAN_ONLY=1;; --skip-tests) SKIP_TESTS=1;; --no-seed) SEED=off;; esac; done
need gcloud; need terraform; need bq; need python3
export TF_VAR_seed_mode="${SEED_MODE:-$SEED}"

log "Project $PROJECT_ID · $REGION · admin $ADMIN_EMAIL · lab resources: $TF_VAR_seed_mode"
log "1/8 Terraform state bucket"
"$ROOT/scripts/bootstrap.sh" "$PROJECT_ID" "$REGION" >/dev/null && ok "gs://$STATE_BUCKET"
tf_init
[ "$PLAN_ONLY" = 1 ] && { $TF plan -input=false; exit 0; }

log "2/8 Phase 1: dataset, views, IAM, alerts, registry, lab misconfigurations"
tf_apply
out() { $TF output -raw "$1"; }
REPO="$(out artifact_repo)"; BUCKET="$(out build_bucket)"; BUILD_SA="$(out build_sa)"

log "3/8 Build the image (Cloud Build, dedicated least-privilege SA)"
TAG="v$(date +%y%m%d-%H%M%S)"
gcloud builds submit --project "$PROJECT_ID" --region "$REGION" --config cloudbuild.yaml \
  --service-account "projects/$PROJECT_ID/serviceAccounts/$BUILD_SA" \
  --gcs-source-staging-dir "gs://$BUCKET/src" --substitutions "_REPO=$REPO,_TAG=$TAG" .
DIGEST="$(gcloud artifacts docker images describe "$REPO/posture:$TAG" --format='get(image_summary.digest)')"
IMG="$REPO/posture@$DIGEST"; ok "image $IMG"; echo "$IMG" > "$ROOT/.last-image"

log "4/8 Phase 2: scan job + private dashboard + scheduler"
tf_apply
ok "job $(out job_name) · dashboard $(out ui_service) · scheduler $(out scheduler_job)"

log "5/8 First scan (don't wait for tomorrow's schedule)"
EXEC="$(run_scan)"; ok "execution $EXEC finished"

log "6/8 Shift-left source: Checkov on the IaC samples and this repo's own Terraform"
"$ROOT/scripts/ingest-checkov.sh"

if [ "$SKIP_TESTS" = 1 ]; then log "Skipping tests"; else log "7/8 Live test suite"; "$ROOT/scripts/test.sh"; fi
log "8/8 DONE — dashboard: ./scripts/dashboard.sh · tear down: ./scripts/down.sh"
