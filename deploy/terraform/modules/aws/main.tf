# CloudTrail management events and console sign-ins flow through EventBridge
# to the IVAR cloud receiver; a scoped policy grants the aws-responder only
# the two actions its manifest declares.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.0" }
  }
}

variable "receiver_url" {
  description = "Base URL of ivar-connector cloud, e.g. https://ivar-cloud.example.com"
  type        = string
}

variable "token" {
  description = "Shared secret the receiver checks in X-Ivar-Token"
  type        = string
  sensitive   = true
}

variable "name" {
  type    = string
  default = "ivar"
}

variable "isolation_security_group_id" {
  description = "Security group host.isolate moves an instance into; empty disables the permission"
  type        = string
  default     = ""
}

resource "aws_cloudwatch_event_connection" "ivar" {
  name               = "${var.name}-receiver"
  authorization_type = "API_KEY"
  auth_parameters {
    api_key {
      key   = "X-Ivar-Token"
      value = var.token
    }
  }
}

resource "aws_cloudwatch_event_api_destination" "ivar" {
  name                             = "${var.name}-receiver"
  connection_arn                   = aws_cloudwatch_event_connection.ivar.arn
  invocation_endpoint              = "${trimsuffix(var.receiver_url, "/")}/aws"
  http_method                      = "POST"
  invocation_rate_limit_per_second = 300
}

resource "aws_cloudwatch_event_rule" "cloudtrail" {
  name        = "${var.name}-cloudtrail"
  description = "CloudTrail API calls and console sign-ins to IVAR"
  event_pattern = jsonencode({
    "detail-type" = ["AWS API Call via CloudTrail", "AWS Console Sign In via CloudTrail"]
  })
}

data "aws_iam_policy_document" "events_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "events" {
  name               = "${var.name}-eventbridge"
  assume_role_policy = data.aws_iam_policy_document.events_assume.json
}

resource "aws_iam_role_policy" "events" {
  role = aws_iam_role.events.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["events:InvokeApiDestination"], Resource = [aws_cloudwatch_event_api_destination.ivar.arn] }]
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "${var.name}-receiver-dlq"
  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_event_target" "ivar" {
  rule     = aws_cloudwatch_event_rule.cloudtrail.name
  arn      = aws_cloudwatch_event_api_destination.ivar.arn
  role_arn = aws_iam_role.events.arn
  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 10
  }
  # Undelivered events are kept, never dropped, so the gap stays visible.
  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

# Scoped credentials for the aws-responder plugin: exactly api_key.suspend
# and host.isolate.
resource "aws_iam_policy" "responder" {
  name = "${var.name}-aws-responder"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{ Effect = "Allow", Action = ["iam:UpdateAccessKey"], Resource = "*" }],
      var.isolation_security_group_id == "" ? [] : [{
        Effect    = "Allow"
        Action    = ["ec2:ModifyInstanceAttribute"]
        Resource  = "*"
        Condition = { StringEquals = { "ec2:Attribute" = "GroupId" } }
      }]
    )
  })
}

output "responder_policy_arn" {
  value = aws_iam_policy.responder.arn
}

output "dead_letter_queue_url" {
  value = aws_sqs_queue.dlq.url
}
