"""Read-only findings dashboard. Private Cloud Run service (no allUsers): reach it with
`gcloud run services proxy` or an identity token. It only ever runs SELECTs against the
two views the Terraform creates, as a service account that can read nothing else."""

from __future__ import annotations

import os

from flask import Flask, jsonify, render_template_string
from google.cloud import bigquery

PROJECT_ID = os.environ["PROJECT_ID"]
DATASET = os.environ.get("DATASET", "posture")
app = Flask(__name__)
_bq: bigquery.Client | None = None


def bq() -> bigquery.Client:
    global _bq
    if _bq is None:
        _bq = bigquery.Client(project=PROJECT_ID)
    return _bq


def query(view: str, limit: int = 500) -> list[dict]:
    rows = bq().query(f"SELECT * FROM `{PROJECT_ID}.{DATASET}.{view}` LIMIT {int(limit)}").result()
    return [dict(r) for r in rows]


def short(resource: str) -> str:
    return resource.rsplit("/", 1)[-1] if "/" in resource and ":" not in resource.rsplit("/", 1)[-1] else resource


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Posture findings · {{ project }}</title>
<style>
:root{--bg:#0f1419;--panel:#171d25;--line:#2a3441;--fg:#e6edf3;--mut:#8b98a8;--crit:#ff5c6c;--high:#ff9d4d;--med:#f2cc60;--low:#6cb6ff;--ok:#56d364}
@media (prefers-color-scheme:light){:root{--bg:#f6f8fa;--panel:#fff;--line:#d0d7de;--fg:#1f2328;--mut:#59636e;--crit:#cf222e;--high:#bc4c00;--med:#9a6700;--low:#0969da;--ok:#1a7f37}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1180px;margin:0 auto;padding:24px 16px 64px}h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;margin:32px 0 10px}
.sub{color:var(--mut);margin:0 0 20px}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px 14px}.tile b{display:block;font-size:26px;line-height:1.1}
.tile span{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.CRITICAL b{color:var(--crit)}.HIGH b{color:var(--high)}.MEDIUM b{color:var(--med)}.LOW b{color:var(--low)}
.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px;background:var(--panel)}
table{border-collapse:collapse;width:100%;min-width:720px}th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}tr:last-child td{border-bottom:0}
.chip{display:inline-block;padding:1px 8px;border-radius:99px;font-size:11px;font-weight:700;border:1px solid currentColor}
.chip.CRITICAL{color:var(--crit)}.chip.HIGH{color:var(--high)}.chip.MEDIUM{color:var(--med)}.chip.LOW{color:var(--low)}.chip.INFO{color:var(--mut)}
code{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--mut);word-break:break-all}.mut{color:var(--mut)}.ok{color:var(--ok)}
.rem{color:var(--mut);font-size:12px;margin-top:2px}
td.rule code{white-space:nowrap;word-break:normal}
</style></head><body><main>
<h1>Posture findings</h1>
<p class="sub">Project <code>{{ project }}</code> · sources: {{ sources|join(', ') or 'none yet' }} · last scan {{ last_scan or 'never' }}</p>
<div class="tiles">
{% for sev in ['CRITICAL','HIGH','MEDIUM','LOW'] %}<div class="tile {{ sev }}"><b>{{ counts.get(sev,0) }}</b><span>{{ sev }} open</span></div>{% endfor %}
<div class="tile"><b class="ok">{{ resolved|length }}</b><span>resolved (recent)</span></div>
</div>
<h2>Open findings ({{ open|length }})</h2>
<div class="wrap"><table><thead><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>Frameworks</th><th>First seen</th></tr></thead><tbody>
{% for f in open %}<tr><td><span class="chip {{ f.severity }}">{{ f.severity }}</span></td><td class="rule"><code>{{ f.rule_id }}</code><br><span class="mut">{{ f.source }}</span></td>
<td><b>{{ f.title }}</b><br>{{ f.evidence }}<div class="rem">Fix: {{ f.remediation }}</div><code>{{ f.resource }}</code></td>
<td>{{ (f.frameworks or [])|join(', ') or '—' }}</td><td class="mut">{{ f.first_seen.strftime('%Y-%m-%d %H:%M') if f.first_seen else '' }}</td></tr>
{% else %}<tr><td colspan="5" class="ok">No open findings.</td></tr>{% endfor %}
</tbody></table></div>
<h2>Recently resolved</h2>
<div class="wrap"><table><thead><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>Resolved</th></tr></thead><tbody>
{% for f in resolved %}<tr><td><span class="chip {{ f.severity }}">{{ f.severity }}</span></td><td class="rule"><code>{{ f.rule_id }}</code></td><td>{{ f.evidence }}</td>
<td class="mut">{{ f.resolved_at.strftime('%Y-%m-%d %H:%M') if f.resolved_at else '' }}</td></tr>
{% else %}<tr><td colspan="4" class="mut">Nothing resolved yet.</td></tr>{% endfor %}
</tbody></table></div>
<h2>Scan history</h2>
<div class="wrap"><table><thead><tr><th>When (UTC)</th><th>Source</th><th>Assets</th><th>Findings</th><th>Opened</th><th>Resolved</th></tr></thead><tbody>
{% for s in scans %}<tr><td>{{ s.scan_time.strftime('%Y-%m-%d %H:%M') }}</td><td>{{ s.source }}</td><td>{{ s.assets_scanned }}</td><td>{{ s.findings_total }}</td><td>{{ s.opened }}</td><td>{{ s.resolved }}</td></tr>{% endfor %}
</tbody></table></div>
</main></body></html>"""


@app.get("/")
def index():
    open_rows = query("v_open_findings")
    counts: dict[str, int] = {}
    for f in open_rows:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    scans = query("v_scan_history", 20)
    return render_template_string(
        PAGE,
        project=PROJECT_ID,
        open=open_rows,
        counts=counts,
        resolved=query("v_recently_resolved", 25),
        scans=scans,
        last_scan=scans[0]["scan_time"].strftime("%Y-%m-%d %H:%M UTC") if scans else None,
        sources=sorted({s["source"] for s in scans}),
    )


@app.get("/api/findings")
def api_findings():
    return jsonify(query("v_open_findings"))
