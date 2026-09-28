#!/usr/bin/env bash
# Open the private dashboard: `gcloud run services proxy` adds your identity token to
# requests, so no public access is needed.   ./scripts/dashboard.sh [port]
source "$(dirname "$0")/lib.sh"
PORT="${1:-8088}"
SVC="$($TF output -raw ui_service)"
log "http://localhost:$PORT  (Ctrl-C to stop)"
gcloud run services proxy "$SVC" --project "$PROJECT_ID" --region "$REGION" --port "$PORT"
