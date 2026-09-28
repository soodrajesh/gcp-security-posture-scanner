# The scan is a job (no inbound traffic, runs on a schedule, bills nothing between runs).
resource "google_cloud_run_v2_job" "scanner" {
  count               = var.image == "" ? 0 : 1
  project             = var.project_id
  name                = "posture-scanner"
  location            = var.region
  deletion_protection = false

  template {
    template {
      service_account = local.sa_email["posture-scanner"]
      max_retries     = 1
      timeout         = "540s"
      containers {
        image = var.image
        env {
          name  = "PROJECT_ID"
          value = var.project_id
        }
        env {
          name  = "DATASET"
          value = google_bigquery_dataset.posture.dataset_id
        }
        env {
          name  = "TOPIC_ID"
          value = google_pubsub_topic.critical_findings.name
        }
        resources {
          limits = { cpu = "1", memory = "512Mi" }
        }
      }
    }
  }
  depends_on = [
    google_project_iam_member.scanner_asset_viewer,
    google_bigquery_dataset_iam_member.scanner_editor,
    google_project_iam_member.job_user,
    google_pubsub_topic_iam_member.scanner_publish,
    google_project_iam_member.log_writer,
  ]
}

# The dashboard: private (there is deliberately no allUsers binding). Reach it with
# `gcloud run services proxy` — see scripts/dashboard.sh.
resource "google_cloud_run_v2_service" "ui" {
  count               = var.image == "" ? 0 : 1
  project             = var.project_id
  name                = "posture-ui"
  location            = var.region
  deletion_protection = false
  ingress             = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = local.sa_email["posture-ui"]
    scaling {
      min_instance_count = 0
      max_instance_count = 2
    }
    containers {
      image   = var.image
      command = ["gunicorn"]
      args    = ["--bind", ":8080", "--workers", "1", "--threads", "4", "ui.main:app"]
      env {
        name  = "PROJECT_ID"
        value = var.project_id
      }
      env {
        name  = "DATASET"
        value = google_bigquery_dataset.posture.dataset_id
      }
      resources {
        limits = { cpu = "1", memory = "512Mi" }
      }
    }
  }
  depends_on = [
    google_bigquery_dataset_iam_member.ui_viewer,
    google_project_iam_member.job_user,
    google_bigquery_table.v_open_findings,
  ]
}

resource "google_cloud_run_v2_service_iam_member" "operator_invoker" {
  count    = var.image == "" ? 0 : 1
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.ui[0].name
  role     = "roles/run.invoker"
  member   = "user:${var.admin_email}"
}
