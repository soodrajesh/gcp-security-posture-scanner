resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Posture scanner alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
  depends_on   = [google_project_service.apis]
}

# The job logs one JSON line per newly-opened HIGH/CRITICAL finding with `alert: true`
# (see app/scanner/main.py::publish_alerts). Cloud Run parses JSON stdout into jsonPayload.
resource "google_logging_metric" "new_findings" {
  project     = var.project_id
  name        = "posture_new_urgent_findings"
  description = "Newly opened HIGH/CRITICAL posture findings."
  filter      = <<-EOT
    resource.type="cloud_run_job"
    resource.labels.job_name="posture-scanner"
    jsonPayload.alert=true
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

resource "google_monitoring_alert_policy" "new_findings" {
  project      = var.project_id
  display_name = "Posture: new HIGH/CRITICAL finding"
  combiner     = "OR"
  conditions {
    display_name = "any new urgent finding in the last 24h"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.new_findings.name}\" AND resource.type=\"cloud_run_job\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"
      aggregations {
        alignment_period   = "86400s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
  documentation {
    content   = "The scanner opened at least one new HIGH or CRITICAL finding. Open the dashboard (scripts/dashboard.sh) or query posture.v_open_findings. Runbook: docs/runbooks/03-triage-a-finding.md"
    mime_type = "text/markdown"
  }
}

resource "google_monitoring_alert_policy" "job_failed" {
  count        = var.image == "" ? 0 : 1
  project      = var.project_id
  display_name = "Posture: scan job execution failed"
  combiner     = "OR"
  conditions {
    display_name = "any failed execution of posture-scanner"
    condition_threshold {
      filter          = "metric.type=\"run.googleapis.com/job/completed_execution_count\" AND resource.type=\"cloud_run_job\" AND resource.label.job_name=\"posture-scanner\" AND metric.label.result=\"failed\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"
      aggregations {
        alignment_period   = "3600s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
  depends_on            = [google_cloud_run_v2_job.scanner]
}
