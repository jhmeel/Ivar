# Cloud Audit Logs for a project flow through a log sink and Pub/Sub push to
# the IVAR cloud receiver.

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = { source = "hashicorp/google", version = ">= 5.0" }
  }
}

variable "receiver_url" {
  type = string
}

variable "token" {
  type      = string
  sensitive = true
}

variable "project" {
  type = string
}

variable "name" {
  type    = string
  default = "ivar"
}

resource "google_pubsub_topic" "audit" {
  project = var.project
  name    = "${var.name}-audit"
}

resource "google_logging_project_sink" "audit" {
  project                = var.project
  name                   = "${var.name}-audit"
  destination            = "pubsub.googleapis.com/${google_pubsub_topic.audit.id}"
  filter                 = "logName:\"cloudaudit.googleapis.com\""
  unique_writer_identity = true
}

resource "google_pubsub_topic_iam_member" "sink_writer" {
  project = var.project
  topic   = google_pubsub_topic.audit.name
  role    = "roles/pubsub.publisher"
  member  = google_logging_project_sink.audit.writer_identity
}

resource "google_pubsub_topic" "dead_letter" {
  project = var.project
  name    = "${var.name}-audit-dead-letter"
}

resource "google_pubsub_subscription" "push" {
  project              = var.project
  name                 = "${var.name}-receiver"
  topic                = google_pubsub_topic.audit.id
  ack_deadline_seconds = 30

  push_config {
    # Pub/Sub push cannot set headers, so the token rides in the query.
    push_endpoint = "${trimsuffix(var.receiver_url, "/")}/gcp?token=${var.token}"
  }

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.dead_letter.id
    max_delivery_attempts = 20
  }
}
