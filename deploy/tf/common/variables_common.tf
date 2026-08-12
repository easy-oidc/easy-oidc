# Easy OIDC <https://easy-oidc.dev>
# Copyright The Easy OIDC Authors
# SPDX-License-Identifier: Apache-2.0

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
  default     = "easy-oidc"
}

variable "oidc_addr" {
  description = "OIDC server address (e.g., 'auth.example.com' or 'auth.example.com:8443')"
  type        = string
}

variable "run_db_migrations" {
  description = "Run state database migrations before every Easy OIDC service start. Enabling this grants the instance access to state_database.migrations.connection_string_secret when configured."
  type        = bool
  default     = false
}

variable "enable_ipv4" {
  description = "Enable public IPv4 address support"
  type        = bool
  default     = true
}

variable "enable_ipv6" {
  description = "Enable public IPv6 address support"
  type        = bool
  default     = true
}

variable "allowed_cidrs_ipv4" {
  description = "Allowed IPv4 CIDRs for HTTP/HTTPS access (ignored if enable_ipv4 = false)"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "allowed_cidrs_ipv6" {
  description = "Allowed IPv6 CIDRs for HTTP/HTTPS access"
  type        = list(string)
  default     = ["::/0"]
}

variable "ssh_allowed_cidrs_ipv4" {
  description = "Allowed IPv4 CIDRs for SSH access when SSH keys are configured"
  type        = list(string)
  default     = []
}

variable "ssh_allowed_cidrs_ipv6" {
  description = "Allowed IPv6 CIDRs for SSH access when SSH keys are configured"
  type        = list(string)
  default     = []
}

variable "instance_disk_size_gb" {
  description = "Instance boot disk size in GB"
  type        = number
  default     = 10

  validation {
    condition     = floor(var.instance_disk_size_gb) == var.instance_disk_size_gb && var.instance_disk_size_gb >= 10
    error_message = "instance_disk_size_gb must be a whole number of at least 10."
  }
}

variable "easy_oidc_version" {
  description = "Easy OIDC release to install; must be v2.0.0 or later, or latest"
  type        = string
  default     = "latest"

  validation {
    condition     = var.easy_oidc_version == "latest" || can(regex("^v(?:[2-9]|[1-9][0-9]+)\\.(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)$", var.easy_oidc_version))
    error_message = "easy_oidc_version must be latest or a final Easy OIDC release tag of v2.0.0 or later."
  }
}

variable "caddy_version" {
  description = "Version of Caddy to install (or 'latest' to use script default)"
  type        = string
  default     = "latest"
}
