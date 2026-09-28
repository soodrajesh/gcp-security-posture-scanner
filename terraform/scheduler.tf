# Cloud Scheduler calls the Cloud Run Admin API's jobs.run directly, authenticated with an
# OAuth token minted for the scheduler's own service account — no keys, no shared secret.
resource "google_cloud_scheduler_job" "daily_scan" {
  count       = var.image == "" ? 0 : 1
  project     = var.project_id
  region      = var.region
  name        = "posture-daily-scan"
  description = "Runs the posture scan once a day."
  schedule    = var.schedule_cron
  time_zone   = "Etc/UTC"

  http_target {
    http_method = "POST"
    uri         = "https://${var.region}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${var.project_id}/jobs/${google_cloud_run_v2_job.scanner[0].name}:run"
    oauth_token {
      service_account_email = local.sa_email["posture-scheduler"]
    }
  }

  depends_on = [google_cloud_run_v2_job_iam_member.scheduler_invoker]
}
