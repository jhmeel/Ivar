# Connectors for all three clouds and the signed policy, in one apply.

variable "receiver_url" { type = string }
variable "receiver_token" {
  type      = string
  sensitive = true
}
variable "azure_subscription_id" { type = string }
variable "gcp_project" { type = string }

provider "aws" {}
provider "azurerm" {
  features {}
}
provider "google" {}

module "policy" {
  source        = "../../modules/policy"
  source_file   = "${path.root}/../../../policy/policy.yaml"
  watched_files = ["${path.root}/../../../policy/time-locks.yaml", "${path.root}/../../../policy/openapi.yaml"]
  key_files     = ["keys/policy-a.seed", "keys/policy-b.seed"]
}

module "aws" {
  source       = "../../modules/aws"
  receiver_url = var.receiver_url
  token        = var.receiver_token
}

module "azure" {
  source          = "../../modules/azure"
  receiver_url    = var.receiver_url
  token           = var.receiver_token
  subscription_id = var.azure_subscription_id
}

module "gcp" {
  source       = "../../modules/gcp"
  receiver_url = var.receiver_url
  token        = var.receiver_token
  project      = var.gcp_project
}
