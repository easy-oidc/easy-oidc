# Easy OIDC <https://easy-oidc.dev>
# Copyright The Easy OIDC Authors
# SPDX-License-Identifier: Apache-2.0

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "vpc_id" {
  description = "VPC ID where easy-oidc will be deployed"
  type        = string
}

variable "subnet_id" {
  description = "Subnet ID for the instance (auto-created if omitted)"
  type        = string
  default     = null
}

variable "secrets_provider" {
  description = "AWS secrets backend used by Easy OIDC"
  type        = string
  default     = "aws-parameter-store"

  validation {
    condition     = contains(["aws-parameter-store", "aws-secrets-manager"], var.secrets_provider)
    error_message = "secrets_provider must be aws-parameter-store or aws-secrets-manager."
  }
}

variable "instance_type" {
  description = "EC2 instance type; its architecture selects the matching Debian image and release artifacts"
  type        = string
  default     = "t4g.nano"
}

variable "kms_key_id" {
  description = "KMS key ID/ARN for EBS volume encryption (uses AWS managed key if not specified)"
  type        = string
  default     = null
}

variable "ssh_key_name" {
  description = "Name of existing AWS key pair for SSH access (leave null to disable SSH)"
  type        = string
  default     = null
}
