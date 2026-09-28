output "artifact_repo" { value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.images.repository_id}" }
output "build_bucket" { value = google_storage_bucket.build.name }
output "build_sa" { value = local.sa_email["posture-build"] }
output "dataset" { value = google_bigquery_dataset.posture.dataset_id }
output "topic" { value = google_pubsub_topic.critical_findings.name }
output "verify_subscription" { value = google_pubsub_subscription.verify.name }
output "job_name" { value = var.image == "" ? "" : google_cloud_run_v2_job.scanner[0].name }
output "ui_service" { value = var.image == "" ? "" : google_cloud_run_v2_service.ui[0].name }
output "scheduler_job" { value = var.image == "" ? "" : google_cloud_scheduler_job.daily_scan[0].name }
output "log_metric" { value = google_logging_metric.new_findings.name }
