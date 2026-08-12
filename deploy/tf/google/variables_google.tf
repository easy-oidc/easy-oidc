# Easy OIDC <https://easy-oidc.dev>
# Copyright The Easy OIDC Authors
# SPDX-License-Identifier: Apache-2.0

variable "labels" {
  description = "Additional labels to apply to supported resources"
  type        = map(string)
  default     = {}
}

variable "project_id" {
  description = "Google Cloud project ID. If null, uses the project from the Google provider configuration."
  type        = string
  default     = null
}

variable "region" {
  description = "Google Cloud region for regional resources. If null, uses the region from the Google provider configuration."
  type        = string
  default     = null
}

variable "zone" {
  description = "Google Cloud zone for the Compute Engine instance. If null, uses the zone from the Google provider configuration."
  type        = string
  default     = null
}

variable "network" {
  description = "VPC network name, self-link, or ID where easy-oidc will be deployed"
  type        = string
}

variable "subnetwork" {
  description = "Subnetwork name, self-link, or ID for the instance. If null, a public subnetwork is created."
  type        = string
  default     = null
}

variable "subnetwork_cidr" {
  description = "IPv4 CIDR range for the auto-created subnetwork"
  type        = string
  default     = "10.0.0.0/24"
}

variable "machine_type" {
  description = "Compute Engine machine type"
  type        = string
  default     = "e2-micro"
}

variable "boot_disk_type" {
  description = "Boot disk type"
  type        = string
  default     = "pd-balanced"
}

variable "boot_disk_kms_key_self_link" {
  description = "Cloud KMS key self-link for boot disk encryption. If null, Google-managed encryption is used."
  type        = string
  default     = null
}

variable "service_account_email" {
  description = "Existing service account email to attach to the instance. If null, one is created."
  type        = string
  default     = null
}

variable "grant_secret_accessor" {
  description = "Grant the instance service account access to each secret referenced by easy_oidc_config. Disable if permissions are managed externally."
  type        = bool
  default     = true
}

variable "ssh_keys" {
  description = "Optional SSH public keys for instance metadata, in GCE metadata format (username:ssh-rsa ...). Leave empty to disable SSH in userdata."
  type        = list(string)
  default     = []
}
