# One identity per job to be done, no keys anywhere. The scanner is READ-ONLY on the project
# (roles/cloudasset.viewer) and writes only to its own dataset and topic.
locals {
  sas = {
    "posture-scanner"   = "Cloud Run Job: reads Cloud Asset Inventory, writes findings, publishes alerts"
    "posture-ui"        = "Cloud Run service: read-only SELECTs on the dashboard views"
    "posture-scheduler" = "Cloud Scheduler: may only start the scan job"
    "posture-build"     = "Cloud Build: builds and pushes the image"
  }
}

resource "google_service_account" "sa" {
  for_each     = local.sas
  project      = var.project_id
  account_id   = each.key
  display_name = each.value
  depends_on   = [google_project_service.apis]
}

locals {
  sa_email = { for k, v in google_service_account.sa : k => v.email }
}

# ── scanner ──
resource "google_project_iam_member" "scanner_asset_viewer" {
  project = var.project_id
  role    = "roles/cloudasset.viewer"
  member  = "serviceAccount:${local.sa_email["posture-scanner"]}"
}

resource "google_bigquery_dataset_iam_member" "scanner_editor" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.posture.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${local.sa_email["posture-scanner"]}"
}

# Running a query job always needs jobUser at project level; there is no dataset-scoped equivalent.
resource "google_project_iam_member" "job_user" {
  for_each = toset(["posture-scanner", "posture-ui"])
  project  = var.project_id
  role     = "roles/bigquery.jobUser"
  member   = "serviceAccount:${local.sa_email[each.key]}"
}

resource "google_pubsub_topic_iam_member" "scanner_publish" {
  project = var.project_id
  topic   = google_pubsub_topic.critical_findings.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${local.sa_email["posture-scanner"]}"
}

resource "google_project_iam_member" "log_writer" {
  for_each = toset(["posture-scanner", "posture-ui", "posture-build"])
  project  = var.project_id
  role     = "roles/logging.logWriter"
  member   = "serviceAccount:${local.sa_email[each.key]}"
}

# ── dashboard: dataset-level viewer only ──
resource "google_bigquery_dataset_iam_member" "ui_viewer" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.posture.dataset_id
  role       = "roles/bigquery.dataViewer"
  member     = "serviceAccount:${local.sa_email["posture-ui"]}"
}

# ── scheduler: may invoke only the scan job ──
resource "google_cloud_run_v2_job_iam_member" "scheduler_invoker" {
  count    = var.image == "" ? 0 : 1
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_job.scanner[0].name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${local.sa_email["posture-scheduler"]}"
}

# ── build ──
resource "google_artifact_registry_repository" "images" {
  project       = var.project_id
  location      = var.region
  repository_id = "posture"
  format        = "DOCKER"
  depends_on    = [google_project_service.apis]
}

resource "google_storage_bucket" "build" {
  project                     = var.project_id
  name                        = "${var.project_id}-posture-build"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true
  versioning {
    enabled = true
  }
  lifecycle_rule {
    condition {
      age = 7
    }
    action {
      type = "Delete"
    }
  }
}

resource "google_artifact_registry_repository_iam_member" "build_push" {
  project    = var.project_id
  location   = var.region
  repository = google_artifact_registry_repository.images.name
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${local.sa_email["posture-build"]}"
}

resource "google_storage_bucket_iam_member" "build_src" {
  bucket = google_storage_bucket.build.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${local.sa_email["posture-build"]}"
}

# ── operator: run the job by hand, load Checkov findings, open the private dashboard ──
resource "google_project_iam_member" "operator_run" {
  project = var.project_id
  role    = "roles/run.developer"
  member  = "user:${var.admin_email}"
}

resource "google_bigquery_dataset_iam_member" "operator_editor" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.posture.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = "user:${var.admin_email}"
}
