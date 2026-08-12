# Truster <https://truster.dev>
# Copyright The Truster Authors
# SPDX-License-Identifier: Apache-2.0

locals {
  instance_arch = length(regexall("^(t2a|c4a|n4a)-", var.machine_type)) > 0 ? "arm64" : "amd64"
  ssh_enabled   = length(var.ssh_keys) > 0
}
