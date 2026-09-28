"""Run the Rego policy bundle with the `opa` binary. A subprocess (not a Python Rego port)
so the exact same policies run in unit tests, in CI and in the job."""

from __future__ import annotations

import json
import os
import subprocess

POLICY_DIR = os.environ.get("POLICY_DIR", "/srv/policies")
OPA = os.environ.get("OPA_BIN", "opa")


class PolicyError(RuntimeError):
    pass


def _eval(query: str, doc: dict) -> object:
    proc = subprocess.run(
        [OPA, "eval", "--format", "json", "--data", POLICY_DIR, "--stdin-input", query],
        input=json.dumps(doc),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise PolicyError(f"opa eval failed ({proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}")
    result = json.loads(proc.stdout).get("result")
    if not result:
        raise PolicyError(f"opa eval returned no result for {query!r} (undefined)")
    return result[0]["expressions"][0]["value"]


def rules() -> dict:
    return _eval("data.posture.rules", {})  # type: ignore[return-value]


def findings(doc: dict) -> list[dict]:
    # `findings` is a set; with no violations OPA still returns [] (defined but empty).
    return _eval("data.posture.findings", doc)  # type: ignore[return-value]
