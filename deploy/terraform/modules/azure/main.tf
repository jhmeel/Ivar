# Azure Activity Log events for a subscription flow through Event Grid to the
# IVAR cloud receiver. The receiver answers the subscription validation
# handshake itself.

terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = ">= 3.80" }
  }
}

variable "receiver_url" {
  type = string
}

variable "token" {
  type      = string
  sensitive = true
}

variable "subscription_id" {
  description = "Subscription whose resource and role changes are streamed"
  type        = string
}

variable "name" {
  type    = string
  default = "ivar"
}

resource "azurerm_eventgrid_event_subscription" "ivar" {
  name  = "${var.name}-receiver"
  scope = "/subscriptions/${var.subscription_id}"

  webhook_endpoint {
    url = "${trimsuffix(var.receiver_url, "/")}/azure"
  }

  included_event_types = [
    "Microsoft.Resources.ResourceWriteSuccess",
    "Microsoft.Resources.ResourceDeleteSuccess",
    "Microsoft.Resources.ResourceActionSuccess",
  ]

  delivery_property {
    header_name = "X-Ivar-Token"
    type        = "Static"
    value       = var.token
    secret      = true
  }

  retry_policy {
    max_delivery_attempts = 30
    event_time_to_live    = 1440
  }
}
