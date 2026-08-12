# Truster <https://truster.dev>
# Copyright The Truster Authors
# SPDX-License-Identifier: Apache-2.0

# EC2 instance with pre-created ENI for stable IPs
resource "aws_launch_template" "main" {
  name_prefix   = "${var.name_prefix}-"
  image_id      = data.aws_ami.debian.id
  instance_type = var.instance_type
  key_name      = var.ssh_key_name

  iam_instance_profile {
    name = aws_iam_instance_profile.instance_profile.name
  }

  network_interfaces {
    network_interface_id = aws_network_interface.main.id
    device_index         = 0
  }

  user_data = base64encode(local.userdata)

  block_device_mappings {
    device_name = data.aws_ami.debian.root_device_name
    ebs {
      encrypted   = true
      kms_key_id  = var.kms_key_id
      volume_size = var.instance_disk_size_gb
      volume_type = "gp3"
    }
  }

  tag_specifications {
    resource_type = "instance"
    tags = merge(
      var.tags,
      {
        Name = var.name_prefix
      }
    )
  }

  lifecycle {
    precondition {
      condition     = var.enable_ipv4 || var.enable_ipv6
      error_message = "At least one of enable_ipv4 or enable_ipv6 must be true so the instance can download dependencies and serve OIDC traffic."
    }
  }
}

resource "aws_instance" "main" {
  launch_template {
    id      = aws_launch_template.main.id
    version = aws_launch_template.main.latest_version
  }
}
