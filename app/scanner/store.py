"""BigQuery persistence: raw inventory snapshots, the findings table with its lifecycle
(open -> resolved -> reopened), and per-scan history.

A finding's lifecycle is decided by one MERGE per (source, project): fingerprints in the
current scan are opened/refreshed; fingerprints that were open but are absent from this
scan for the same source+project are marked resolved. Sources never resolve each other's
findings.
"""

from __future__ import annotations

import json
from datetime import datetime

from google.cloud import bigquery

FINDING_COLUMNS = [
    "finding_id", "source", "rule_id", "title", "severity", "severity_rank", "frameworks",
    "resource", "resource_type", "subject", "evidence", "remediation", "project_id",
    "status", "first_seen", "last_seen", "resolved_at", "last_scan_id",
]  # fmt: skip


class Store:
    def __init__(self, project_id: str, dataset: str, client: bigquery.Client | None = None):
        self.project_id = project_id
        self.bq = client or bigquery.Client(project=project_id)
        self.ds = f"`{project_id}.{dataset}`"
        self.dataset = dataset

    def _table(self, name: str) -> str:
        return f"{self.project_id}.{self.dataset}.{name}"

    def save_inventory(self, scan_id: str, scan_time: str, snapshot: dict) -> int:
        rows = []
        for content_type, key, body_key in (
            ("RESOURCE", "resources", "data"),
            ("IAM_POLICY", "iam", "policy"),
        ):
            for a in snapshot[key]:
                rows.append({
                    "scan_id": scan_id, "scan_time": scan_time, "content_type": content_type,
                    "asset_type": a["asset_type"], "name": a["name"], "body": a[body_key],
                })  # fmt: skip
        if rows:
            job = self.bq.load_table_from_json(
                rows, self._table("assets"),
                job_config=bigquery.LoadJobConfig(write_disposition="WRITE_APPEND"),
            )  # fmt: skip
            job.result()
        return len(rows)

    def _scalar_rows(self, sql: str, params: list) -> list[dict]:
        job = self.bq.query(sql, job_config=bigquery.QueryJobConfig(query_parameters=params))
        return [dict(r) for r in job.result()]

    def merge_findings(self, rows: list[dict], source: str, scan_id: str, scan_time: str) -> dict:
        """Stage `rows`, work out what is new / resolved, MERGE, and return the summary plus the
        list of newly opened (or reopened) findings so the caller can alert on them."""
        rows = list({r["finding_id"]: r for r in rows}.values())  # MERGE would insert duplicate source rows twice
        staging = self._table("findings_staging")
        cfg = bigquery.LoadJobConfig(
            write_disposition="WRITE_TRUNCATE",
            schema=self.bq.get_table(self._table("findings")).schema,
        )
        self.bq.load_table_from_json(rows, staging, job_config=cfg).result() if rows else self.bq.query(
            f"TRUNCATE TABLE `{staging}`"
        ).result()

        params = [
            bigquery.ScalarQueryParameter("source", "STRING", source),
            bigquery.ScalarQueryParameter("project", "STRING", self.project_id),
            bigquery.ScalarQueryParameter("scan_time", "TIMESTAMP", datetime.fromisoformat(scan_time.replace("Z", "+00:00"))),
        ]  # fmt: skip
        newly_open = self._scalar_rows(
            f"""SELECT S.* EXCEPT (first_seen, last_seen, resolved_at)
                FROM `{staging}` S LEFT JOIN `{self._table('findings')}` T USING (finding_id)
                WHERE T.finding_id IS NULL OR T.status = 'resolved'
                ORDER BY S.severity_rank DESC, S.rule_id""",
            params,
        )
        resolved = self._scalar_rows(
            f"""SELECT T.finding_id, T.rule_id, T.severity, T.evidence
                FROM `{self._table('findings')}` T LEFT JOIN `{staging}` S USING (finding_id)
                WHERE T.source = @source AND T.project_id = @project AND T.status = 'open' AND S.finding_id IS NULL""",
            params,
        )
        cols = ", ".join(FINDING_COLUMNS)
        vals = ", ".join(f"S.{c}" for c in FINDING_COLUMNS)
        self._scalar_rows(
            f"""MERGE `{self._table('findings')}` T
                USING `{staging}` S ON T.finding_id = S.finding_id
                WHEN MATCHED THEN UPDATE SET
                  status = 'open', resolved_at = NULL, last_seen = S.last_seen, last_scan_id = S.last_scan_id,
                  title = S.title, severity = S.severity, severity_rank = S.severity_rank,
                  frameworks = S.frameworks, evidence = S.evidence, remediation = S.remediation
                WHEN NOT MATCHED BY TARGET THEN INSERT ({cols}) VALUES ({vals})
                WHEN NOT MATCHED BY SOURCE AND T.source = @source AND T.project_id = @project AND T.status = 'open'
                  THEN UPDATE SET status = 'resolved', resolved_at = @scan_time""",
            params,
        )
        by_sev: dict[str, int] = {}
        for r in rows:
            by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1
        return {
            "findings_total": len(rows),
            "opened": len(newly_open),
            "resolved": len(resolved),
            "by_severity": by_sev,
            "newly_open": newly_open,
            "newly_resolved": resolved,
        }

    def record_scan(self, scan_id: str, scan_time: str, source: str, assets: int, summary: dict) -> None:
        row = {
            "scan_id": scan_id, "scan_time": scan_time, "source": source, "project_id": self.project_id,
            "assets_scanned": assets, "findings_total": summary["findings_total"],
            "opened": summary["opened"], "resolved": summary["resolved"],
            "by_severity": json.dumps(summary["by_severity"]),
        }  # fmt: skip
        errors = self.bq.insert_rows_json(self._table("scans"), [row])
        if errors:
            raise RuntimeError(f"recording scan failed: {errors}")
