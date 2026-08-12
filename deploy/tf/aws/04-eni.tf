# Truster <https://truster.dev>
# Copyright The Truster Authors
# SPDX-License-Identifier: Apache-2.0

# Network interface for stable IP addressing
resource "aws_network_interface" "main" {
  subnet_id       = local.instance_subnet_id
  security_groups = [aws_security_group.main.id]

  ipv6_address_count = var.enable_ipv6 ? 1 : 0

  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-eni"
    }
  )
}

# Allocate and associate EIP if IPv4 is enabled
resource "aws_eip" "main" {
  count = var.enable_ipv4 ? 1 : 0

  domain = "vpc"

  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-eip"
    }
  )
}

resource "aws_eip_association" "main" {
  count = var.enable_ipv4 ? 1 : 0

  network_interface_id = aws_network_interface.main.id
  allocation_id        = aws_eip.main[0].id
}
