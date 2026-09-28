variable "project_id" {
  type = string
}

variable "region" {
  type    = string
  default = "europe-west1"
}

variable "alert_email" {
  type = string
}

variable "admin_email" {
  type = string
}

variable "image" {
  description = "Digest-pinned image for the scan job and dashboard. Empty = phase 1 (infrastructure only)."
  type        = string
  default     = ""
}

variable "seed_mode" {
  description = "Deliberately-misconfigured lab resources the scanner should catch: off | vulnerable | hardened (the fixed versions, to demonstrate findings resolving)."
  type        = string
  default     = "off"
  validation {
    condition     = contains(["off", "vulnerable", "hardened"], var.seed_mode)
    error_message = "seed_mode must be off, vulnerable or hardened."
  }
}

variable "schedule_cron" {
  description = "Cloud Scheduler cron expression for the daily scan."
  type        = string
  default     = "30 5 * * *"
}
