# Builds and signs the policy bundle with ivar-control whenever the source,
# its time locks or its declarations change. A change that weakens
# protection fails here unless two policy keys sign it.

terraform {
  required_version = ">= 1.5"
}

variable "source_file" {
  description = "policy.yaml"
  type        = string
}

variable "watched_files" {
  description = "Files the source refers to (time locks, OpenAPI, IAM, ...)"
  type        = list(string)
  default     = []
}

variable "key_files" {
  description = "Policy key seed files that sign the bundle"
  type        = list(string)
}

variable "previous_bundle" {
  description = "Bundle in force, to detect weakening changes"
  type        = string
  default     = ""
}

variable "out" {
  type    = string
  default = "policy.bundle"
}

variable "replay_library" {
  description = "Attack replay library the policy must pass before it is signed"
  type        = string
  default     = "replay-library"
}

variable "ivar_control" {
  description = "Path of the ivar-control binary"
  type        = string
  default     = "ivar-control"
}

resource "terraform_data" "bundle" {
  triggers_replace = [filesha256(var.source_file), [for f in var.watched_files : filesha256(f)], var.key_files]

  provisioner "local-exec" {
    command = join(" ", concat(
      [var.ivar_control, "validate", "--source", var.source_file, "--library", var.replay_library],
      ["&&", var.ivar_control, "build", "--source", var.source_file, "--keys", join(",", var.key_files), "--out", var.out],
      var.previous_bundle == "" ? [] : ["--previous", var.previous_bundle],
    ))
  }
}

output "bundle_path" {
  value      = var.out
  depends_on = [terraform_data.bundle]
}
