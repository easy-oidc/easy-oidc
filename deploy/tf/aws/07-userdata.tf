# Truster <https://truster.dev>
# Copyright The Truster Authors
# SPDX-License-Identifier: Apache-2.0

locals {
  instance_arch     = contains(data.aws_ec2_instance_type.selected.supported_architectures, "arm64") ? "arm64" : "amd64"
  aws_instance_arch = local.instance_arch == "arm64" ? "arm64" : "x86_64"
  ssh_enabled       = var.ssh_key_name != null
}
