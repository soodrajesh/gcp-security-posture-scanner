resource "google_pubsub_topic" "critical_findings" {
  project    = var.project_id
  name       = "posture-new-findings"
  depends_on = [google_project_service.apis]
}

# Pull subscription so scripts/test.sh can prove alert messages arrive, and so a real
# consumer (Slack relay, ticketing) has something to bind to.
resource "google_pubsub_subscription" "verify" {
  project                    = var.project_id
  name                       = "posture-new-findings-verify"
  topic                      = google_pubsub_topic.critical_findings.id
  ack_deadline_seconds       = 20
  message_retention_duration = "86400s"
}
