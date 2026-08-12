# Truster <https://truster.dev>
# Copyright The Truster Authors
# SPDX-License-Identifier: Apache-2.0

# Security group
resource "aws_security_group" "main" {
  name_prefix = "${var.name_prefix}-"
  description = "Allow HTTP & HTTPS traffic to truster"
  vpc_id      = var.vpc_id

  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-sg"
    }
  )
}

resource "aws_vpc_security_group_ingress_rule" "http_ipv4" {
  count = var.enable_ipv4 ? length(var.allowed_cidrs_ipv4) : 0

  security_group_id = aws_security_group.main.id
  description       = "HTTP from IPv4"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  cidr_ipv4         = var.allowed_cidrs_ipv4[count.index]
}

resource "aws_vpc_security_group_ingress_rule" "https_ipv4" {
  count = var.enable_ipv4 ? length(var.allowed_cidrs_ipv4) : 0

  security_group_id = aws_security_group.main.id
  description       = "HTTPS from IPv4"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = var.allowed_cidrs_ipv4[count.index]
}

resource "aws_vpc_security_group_ingress_rule" "http_ipv6" {
  count = var.enable_ipv6 ? length(var.allowed_cidrs_ipv6) : 0

  security_group_id = aws_security_group.main.id
  description       = "HTTP from IPv6"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  cidr_ipv6         = var.allowed_cidrs_ipv6[count.index]
}

resource "aws_vpc_security_group_ingress_rule" "https_ipv6" {
  count = var.enable_ipv6 ? length(var.allowed_cidrs_ipv6) : 0

  security_group_id = aws_security_group.main.id
  description       = "HTTPS from IPv6"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv6         = var.allowed_cidrs_ipv6[count.index]
}

resource "aws_vpc_security_group_egress_rule" "all_ipv4" {
  count = var.enable_ipv4 ? 1 : 0

  security_group_id = aws_security_group.main.id
  description       = "Allow all IPv4 egress"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "all_ipv6" {
  count = var.enable_ipv6 ? 1 : 0

  security_group_id = aws_security_group.main.id
  description       = "Allow all IPv6 egress"
  ip_protocol       = "-1"
  cidr_ipv6         = "::/0"
}

resource "aws_vpc_security_group_ingress_rule" "ssh_ipv4" {
  count = var.enable_ipv4 && var.ssh_key_name != null ? length(var.ssh_allowed_cidrs_ipv4) : 0

  security_group_id = aws_security_group.main.id
  description       = "SSH from IPv4"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
  cidr_ipv4         = var.ssh_allowed_cidrs_ipv4[count.index]
}

resource "aws_vpc_security_group_ingress_rule" "ssh_ipv6" {
  count = var.enable_ipv6 && var.ssh_key_name != null ? length(var.ssh_allowed_cidrs_ipv6) : 0

  security_group_id = aws_security_group.main.id
  description       = "SSH from IPv6"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
  cidr_ipv6         = var.ssh_allowed_cidrs_ipv6[count.index]
}
