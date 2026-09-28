resource "google_bigquery_dataset" "posture" {
  project                    = var.project_id
  dataset_id                 = "posture"
  location                   = var.region
  description                = "Cloud posture scanner: inventory snapshots, normalised findings, scan history."
  delete_contents_on_destroy = true
  depends_on                 = [google_project_service.apis]
}

locals {
  findings_schema = [
    { name = "finding_id", type = "STRING", mode = "REQUIRED", description = "sha256(source|rule|resource|subject)[:16]; stable across scans" },
    { name = "source", type = "STRING", mode = "REQUIRED", description = "cai-rego | checkov" },
    { name = "rule_id", type = "STRING", mode = "REQUIRED" },
    { name = "title", type = "STRING", mode = "NULLABLE" },
    { name = "severity", type = "STRING", mode = "REQUIRED" },
    { name = "severity_rank", type = "INTEGER", mode = "REQUIRED" },
    { name = "frameworks", type = "STRING", mode = "REPEATED" },
    { name = "resource", type = "STRING", mode = "REQUIRED" },
    { name = "resource_type", type = "STRING", mode = "NULLABLE" },
    { name = "subject", type = "STRING", mode = "NULLABLE" },
    { name = "evidence", type = "STRING", mode = "NULLABLE" },
    { name = "remediation", type = "STRING", mode = "NULLABLE" },
    { name = "project_id", type = "STRING", mode = "REQUIRED" },
    { name = "status", type = "STRING", mode = "REQUIRED", description = "open | resolved" },
    { name = "first_seen", type = "TIMESTAMP", mode = "REQUIRED" },
    { name = "last_seen", type = "TIMESTAMP", mode = "REQUIRED" },
    { name = "resolved_at", type = "TIMESTAMP", mode = "NULLABLE" },
    { name = "last_scan_id", type = "STRING", mode = "NULLABLE" },
  ]
}

resource "google_bigquery_table" "findings" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.posture.dataset_id
  table_id            = "findings"
  deletion_protection = false
  schema              = jsonencode(local.findings_schema)
  clustering          = ["status", "severity"]
}

# Scratch table the job loads each scan's findings into before MERGE-ing them.
resource "google_bigquery_table" "findings_staging" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.posture.dataset_id
  table_id            = "findings_staging"
  deletion_protection = false
  schema              = jsonencode(local.findings_schema)
}

resource "google_bigquery_table" "assets" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.posture.dataset_id
  table_id            = "assets"
  deletion_protection = false
  description         = "Raw Cloud Asset Inventory snapshot per scan (30-day partition expiry)."
  time_partitioning {
    type          = "DAY"
    field         = "scan_time"
    expiration_ms = 2592000000
  }
  schema = jsonencode([
    { name = "scan_id", type = "STRING", mode = "REQUIRED" },
    { name = "scan_time", type = "TIMESTAMP", mode = "REQUIRED" },
    { name = "content_type", type = "STRING", mode = "REQUIRED", description = "RESOURCE | IAM_POLICY" },
    { name = "asset_type", type = "STRING", mode = "REQUIRED" },
    { name = "name", type = "STRING", mode = "REQUIRED" },
    { name = "body", type = "JSON", mode = "NULLABLE" },
  ])
}

resource "google_bigquery_table" "scans" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.posture.dataset_id
  table_id            = "scans"
  deletion_protection = false
  schema = jsonencode([
    { name = "scan_id", type = "STRING", mode = "REQUIRED" },
    { name = "scan_time", type = "TIMESTAMP", mode = "REQUIRED" },
    { name = "source", type = "STRING", mode = "REQUIRED" },
    { name = "project_id", type = "STRING", mode = "REQUIRED" },
    { name = "assets_scanned", type = "INTEGER", mode = "NULLABLE" },
    { name = "findings_total", type = "INTEGER", mode = "NULLABLE" },
    { name = "opened", type = "INTEGER", mode = "NULLABLE" },
    { name = "resolved", type = "INTEGER", mode = "NULLABLE" },
    { name = "by_severity", type = "JSON", mode = "NULLABLE" },
  ])
}

# The dashboard reads only these views, never the base tables.
resource "google_bigquery_table" "v_open_findings" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.posture.dataset_id
  table_id            = "v_open_findings"
  deletion_protection = false
  view {
    use_legacy_sql = false
    query          = "SELECT * FROM `${var.project_id}.${google_bigquery_dataset.posture.dataset_id}.findings` WHERE status = 'open' ORDER BY severity_rank DESC, rule_id, resource"
  }
  depends_on = [google_bigquery_table.findings]
}

resource "google_bigquery_table" "v_recently_resolved" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.posture.dataset_id
  table_id            = "v_recently_resolved"
  deletion_protection = false
  view {
    use_legacy_sql = false
    query          = "SELECT * FROM `${var.project_id}.${google_bigquery_dataset.posture.dataset_id}.findings` WHERE status = 'resolved' ORDER BY resolved_at DESC"
  }
  depends_on = [google_bigquery_table.findings]
}

resource "google_bigquery_table" "v_scan_history" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.posture.dataset_id
  table_id            = "v_scan_history"
  deletion_protection = false
  view {
    use_legacy_sql = false
    query          = "SELECT * FROM `${var.project_id}.${google_bigquery_dataset.posture.dataset_id}.scans` ORDER BY scan_time DESC"
  }
  depends_on = [google_bigquery_table.scans]
}
