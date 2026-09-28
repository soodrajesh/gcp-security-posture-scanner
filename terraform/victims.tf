# ── Deliberately misconfigured lab resources ───────────────────────────────────────────────
# The scanner needs something real to find. seed_mode = "vulnerable" creates these;
# "hardened" applies the FIXED versions of the same resources (findings must flip to
# resolved); "off" removes them. Nothing here can be reached or abused:
#   * the VPC has no subnets and no VMs, so its firewall rules protect nothing;
#   * the bucket is empty and short-lived;
#   * the BigQuery dataset is empty and the Cloud Run service is Google's public hello-world image.
# Two misconfigurations one would naturally seed are NOT here because this organization
# already blocks them (org policies storage.uniformBucketLevelAccess and
# iam.disableServiceAccountKeyCreation — the first live run hit both). Their rules
# (GCP-STO-001, GCP-IAM-001/002) are covered by unit tests; see docs/adr/0003.
locals {
  seeded     = var.seed_mode != "off"
  vulnerable = var.seed_mode == "vulnerable"
}

resource "google_compute_network" "seed" {
  count                   = local.seeded ? 1 : 0
  project                 = var.project_id
  name                    = "seed-lab-vpc"
  auto_create_subnetworks = false
  depends_on              = [google_project_service.apis]
}

resource "google_compute_firewall" "seed_ssh" {
  count         = local.seeded ? 1 : 0
  project       = var.project_id
  name          = "seed-allow-ssh"
  network       = google_compute_network.seed[0].name
  direction     = "INGRESS"
  source_ranges = local.vulnerable ? ["0.0.0.0/0"] : ["35.235.240.0/20"] # IAP TCP forwarding range
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "seed_allow_all" {
  count         = local.vulnerable ? 1 : 0
  project       = var.project_id
  name          = "seed-allow-all"
  network       = google_compute_network.seed[0].name
  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "all"
  }
}

resource "google_storage_bucket" "seed" {
  count                       = local.seeded ? 1 : 0
  project                     = var.project_id
  name                        = "${var.project_id}-posture-seed"
  location                    = var.region
  force_destroy               = true
  uniform_bucket_level_access = true # enforced by org policy; the misconfiguration is the public binding below
  public_access_prevention    = local.vulnerable ? "inherited" : "enforced"
}

resource "google_storage_bucket_iam_member" "seed_public" {
  count  = local.vulnerable ? 1 : 0
  bucket = google_storage_bucket.seed[0].name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

resource "google_bigquery_dataset" "seed" {
  count                      = local.seeded ? 1 : 0
  project                    = var.project_id
  dataset_id                 = "seed_lab"
  location                   = var.region
  delete_contents_on_destroy = true
  access {
    role          = "OWNER"
    special_group = "projectOwners"
  }
  dynamic "access" {
    for_each = local.vulnerable ? [1] : []
    content {
      role          = "READER"
      special_group = "allAuthenticatedUsers"
    }
  }
  depends_on = [google_project_service.apis]
}

resource "google_service_account" "seed" {
  count        = local.seeded ? 1 : 0
  project      = var.project_id
  account_id   = "seed-lab-runner"
  display_name = "Posture scanner lab: over-privileged SA"
  depends_on   = [google_project_service.apis]
}

resource "google_project_iam_member" "seed_role" {
  count   = local.seeded ? 1 : 0
  project = var.project_id
  role    = local.vulnerable ? "roles/editor" : "roles/viewer"
  member  = "serviceAccount:${google_service_account.seed[0].email}"
}

resource "google_cloud_run_v2_service" "seed" {
  count               = local.seeded ? 1 : 0
  project             = var.project_id
  name                = "seed-lab-hello"
  location            = var.region
  deletion_protection = false
  template {
    scaling {
      max_instance_count = 1
    }
    containers {
      image = "us-docker.pkg.dev/cloudrun/container/hello"
    }
  }
  depends_on = [google_project_service.apis]
}

resource "google_cloud_run_v2_service_iam_member" "seed_public" {
  count    = local.vulnerable ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.seed[0].name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
