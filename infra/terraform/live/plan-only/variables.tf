variable "region" {
  description = "AWS region used for plan-only examples."
  type        = string
  default     = "us-east-2"
}

variable "environment" {
  description = "Environment tag applied to every resource."
  type        = string
  default     = "lab"
}
