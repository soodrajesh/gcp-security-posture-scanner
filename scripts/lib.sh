#!/usr/bin/env bash
# Shared helpers for up.sh / down.sh / test.sh / remediate.sh. Sourced, not executed.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

log()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m✔ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m! %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m✘ %s\033[0m\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1${2:+ ($2)}"; }

[ -f "$ROOT/deploy.env" ] && set -a && . "$ROOT/deploy.env" && set +a

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}"
REGION="${REGION:-europe-west1}"
ADMIN_EMAIL="${ADMIN_EMAIL:-$(gcloud config get-value account 2>/dev/null)}"
ALERT_EMAIL="${ALERT_EMAIL:-$ADMIN_EMAIL}"
[ -n "$PROJECT_ID" ] || die "no project: set PROJECT_ID in deploy.env or run 'gcloud config set project'"

TF="terraform -chdir=$ROOT/terraform"
STATE_BUCKET="${PROJECT_ID}-tfstate"
# shellcheck disable=SC2034 # used by the scripts that source this file
DATASET="posture"

export TF_VAR_project_id="$PROJECT_ID" TF_VAR_region="$REGION" TF_VAR_alert_email="$ALERT_EMAIL" TF_VAR_admin_email="$ADMIN_EMAIL"

tf_init() { $TF init -input=false -backend-config="bucket=$STATE_BUCKET" >/dev/null; }

wait_for() { # <description> <timeout-seconds> <command...>
  local desc="$1" timeout="$2"; shift 2
  local end=$(( $(date +%s) + timeout ))
  until "$@" >/dev/null 2>&1; do
    [ "$(date +%s)" -lt "$end" ] || die "timed out after ${timeout}s waiting for: $desc"
    sleep 5
  done
  ok "$desc"
}

# BigQuery helper: one scalar out, quiet. Usage: bq_scalar "SELECT ..."
bq_scalar() { bq --project_id "$PROJECT_ID" query --nouse_legacy_sql --quiet --format=csv "$1" 2>/dev/null | tail -1; }

# Apply Terraform with the last built image kept, so re-runs never tear down phase-2 resources.
tf_apply() {
  if [ -s "$ROOT/.last-image" ]; then TF_VAR_image="$(cat "$ROOT/.last-image")"; export TF_VAR_image; fi
  $TF apply -input=false -auto-approve "$@"
}

# Run the scan job and wait. Prints the execution name.
run_scan() {
  local job; job="$($TF output -raw job_name)"
  gcloud run jobs execute "$job" --project "$PROJECT_ID" --region "$REGION" --wait --format='value(metadata.name)'
}
