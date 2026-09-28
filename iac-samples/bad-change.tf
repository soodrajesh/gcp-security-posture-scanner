# A "pull request" that has NOT been deployed: the kind of change Checkov should stop in CI.
# It is scanned by scripts/ingest-checkov.sh and merged as source=checkov. Never applied.
resource "google_compute_firewall" "open_ssh" {
  name          = "pr-open-ssh"
  network       = "default"
  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_storage_bucket" "reports" {
  name                        = "example-reports-bucket"
  location                    = "EU"
  uniform_bucket_level_access = false
}

resource "google_storage_bucket_iam_member" "public_read" {
  bucket = google_storage_bucket.reports.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
