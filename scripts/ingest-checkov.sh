#!/usr/bin/env bash
# Scan Terraform with Checkov and merge the result into the same findings table as a second
# source. Checkov lives in a throwaway venv so nothing is installed globally.
source "$(dirname "$0")/lib.sh"
need python3
VENV="$ROOT/.checkov-venv"
if [ ! -x "$VENV/bin/checkov" ]; then
  python3 -m venv "$VENV" && "$VENV/bin/pip" install -q "checkov==3.2.*" >/dev/null
fi
OUT="$ROOT/.test-tmp"; mkdir -p "$OUT"
# --soft-fail: Checkov exits 1 when it finds anything; we WANT the findings, not a failed script.
"$VENV/bin/checkov" -d iac-samples -d terraform --framework terraform --compact --quiet --soft-fail \
  --skip-path terraform/.terraform -o json > "$OUT/checkov.json" 2>"$OUT/checkov.err" || { tail -5 "$OUT/checkov.err"; die "checkov failed"; }
[ -d "$ROOT/.venv" ] && PY="$ROOT/.venv/bin/python" || PY=python3
PROJECT_ID="$PROJECT_ID" DATASET="$DATASET" PYTHONPATH="$ROOT/app" "$PY" -m scanner.ingest_checkov "$OUT/checkov.json"
