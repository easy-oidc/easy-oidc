mock_provider "google" {
  mock_data "google_client_config" {
    defaults = {
      project = "my-project"
      region  = "us-central1"
      zone    = "us-central1-a"
    }
  }

  mock_resource "google_compute_address" {
    defaults = { address = "203.0.113.10" }
  }
}

mock_provider "http" {
  mock_data "http" {
    defaults = { response_body = "#!/bin/bash\n" }
  }
}

variables {
  project_id      = "my-project"
  region          = "us-central1"
  zone            = "us-central1-a"
  network         = "default"
  subnetwork      = "default"
  oidc_addr       = "auth.example.com"
  truster_version = "v2.0.0"
  caddy_version   = "v2.10.0"

  truster_config = {
    secrets = {
      signing_key_name    = "projects/my-project/secrets/signing/versions/latest"
      encryption_key_name = "projects/my-project/secrets/encryption/versions/latest"
    }
    user_login_connectors = {
      google = {
        type               = "google"
        display_name       = "Google"
        credentials_secret = "projects/my-project/secrets/google/versions/latest"
      }
    }
    static_policy = {
      clients = {
        app = {
          redirect_uris = ["https://app.example/callback"]
        }
      }
    }
  }
}

run "valid_cross_field_configuration" {
  command = plan
}

run "custom_oidc_port_reaches_caddy" {
  command = plan

  variables {
    oidc_addr = "auth.example.com:8443"
  }

  assert {
    condition     = output.issuer_url == "https://auth.example.com:8443"
    error_message = "The issuer URL must retain the custom OIDC port."
  }

  assert {
    condition     = strcontains(google_compute_instance.main.metadata_startup_script, "OIDC_ADDR=auth.example.com:8443")
    error_message = "Userdata must pass the custom OIDC port to Caddy."
  }
}

run "shared_instance_inputs_control_google_resources" {
  command = plan

  variables {
    instance_disk_size_gb  = 20
    ssh_keys               = ["operator:ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest"]
    ssh_allowed_cidrs_ipv4 = ["192.0.2.0/24"]
    ssh_allowed_cidrs_ipv6 = ["2001:db8::/48"]
  }

  assert {
    condition = (
      toset(google_compute_firewall.ssh_ipv4[0].source_ranges) == toset(["192.0.2.0/24"]) &&
      toset(google_compute_firewall.ssh_ipv6[0].source_ranges) == toset(["2001:db8::/48"])
    )
    error_message = "SSH rules must use the dedicated SSH CIDRs for each IP family."
  }

  assert {
    condition     = google_compute_instance.main.boot_disk[0].initialize_params[0].size == 20
    error_message = "instance_disk_size_gb must set the Compute Engine boot disk size."
  }
}

run "ipv6_can_be_disabled" {
  command = plan

  variables {
    enable_ipv6 = false
  }

  assert {
    condition     = output.enable_ipv6 == false
    error_message = "Disabling IPv6 must be reflected in the module output."
  }
}

run "at_least_one_ip_family_is_required" {
  command = plan

  variables {
    enable_ipv4 = false
    enable_ipv6 = false
  }

  expect_failures = [google_compute_instance.main]
}

run "refresh_with_non_email_connector_requires_encryption" {
  command = plan

  variables {
    truster_config = {
      secrets = { signing_key_name = "projects/my-project/secrets/signing/versions/latest" }
      user_login_connectors = {
        google = {
          type               = "google"
          display_name       = "Google"
          credentials_secret = "projects/my-project/secrets/google/versions/latest"
        }
      }
      static_policy = {
        clients = {
          app = {
            redirect_uris  = ["https://app.example/callback"]
            refresh_tokens = { enabled = true }
          }
        }
      }
    }
  }

  expect_failures = [var.truster_config]
}

run "email_delivery_requires_smtp" {
  command = plan

  variables {
    truster_config = {
      secrets = { signing_key_name = "projects/my-project/secrets/signing/versions/latest" }
      user_login_connectors = {
        email = { type = "email", display_name = "Email" }
      }
      email         = { otp_secret_name = "projects/my-project/secrets/otp/versions/latest", otp_ttl = "5m" }
      static_policy = { clients = { app = { redirect_uris = ["https://app.example/callback"] } } }
    }
  }

  expect_failures = [var.truster_config]
}

run "static_client_requires_redirects" {
  command = plan

  variables {
    truster_config = {
      secrets = { signing_key_name = "projects/my-project/secrets/signing/versions/latest" }
      user_login_connectors = {
        google = { type = "google", display_name = "Google", credentials_secret = "projects/my-project/secrets/google/versions/latest" }
      }
      static_policy = { clients = { app = {} } }
    }
  }

  expect_failures = [var.truster_config]
}

run "generic_refresh_cannot_override_owned_parameters" {
  command = plan

  variables {
    truster_config = {
      secrets = { signing_key_name = "projects/my-project/secrets/signing/versions/latest" }
      user_login_connectors = {
        upstream = {
          type               = "generic"
          display_name       = "Upstream"
          credentials_secret = "projects/my-project/secrets/upstream/versions/latest"
          generic = {
            authorization_url = "https://idp.example/authorize"
            token_url         = "https://idp.example/token"
            userinfo_url      = "https://idp.example/userinfo"
            refresh           = { authorization_params = { client_id = "override" } }
          }
        }
      }
      static_policy = { clients = { app = { redirect_uris = ["https://app.example/callback"] } } }
    }
  }

  expect_failures = [var.truster_config]
}

run "refresh_idle_ttl_cannot_exceed_absolute_ttl" {
  command = plan

  variables {
    truster_config = {
      secrets = {
        signing_key_name    = "projects/my-project/secrets/signing/versions/latest"
        encryption_key_name = "projects/my-project/secrets/encryption/versions/latest"
      }
      user_login_connectors = {
        google = { type = "google", display_name = "Google", credentials_secret = "projects/my-project/secrets/google/versions/latest" }
      }
      static_policy = {
        clients = {
          app = {
            redirect_uris = ["https://app.example/callback"]
            refresh_tokens = {
              enabled              = true
              session_idle_ttl     = "1h30m"
              session_absolute_ttl = "1h"
            }
          }
        }
      }
    }
  }

  expect_failures = [var.truster_config]
}

run "preset_service_issuer_fields_cannot_be_overridden" {
  command = plan

  variables {
    truster_config = {
      secrets = { signing_key_name = "projects/my-project/secrets/signing/versions/latest" }
      user_login_connectors = {
        google = { type = "google", display_name = "Google", credentials_secret = "projects/my-project/secrets/google/versions/latest" }
      }
      service_token_issuers = {
        actions = { provider = "github", signing_algs = ["RS256"] }
      }
      static_policy = { clients = { app = { redirect_uris = ["https://app.example/callback"] } } }
    }
  }

  expect_failures = [var.truster_config]
}

run "policy_database_empty_refresh_uses_disabled_default" {
  command = plan

  variables {
    truster_config = {
      secrets = { signing_key_name = "projects/my-project/secrets/signing/versions/latest" }
      user_login_connectors = {
        google = { type = "google", display_name = "Google", credentials_secret = "projects/my-project/secrets/google/versions/latest" }
      }
      policy_database = {
        driver                   = "postgresql"
        connection_string_secret = "projects/my-project/secrets/policy-database/versions/latest"
        redirect_uris            = ["https://app.example/callback"]
        client_defaults          = { refresh_tokens = {} }
      }
    }
  }
}

run "explicit_empty_default_redirects_are_invalid" {
  command = plan

  variables {
    truster_config = {
      secrets = { signing_key_name = "projects/my-project/secrets/signing/versions/latest" }
      user_login_connectors = {
        google = { type = "google", display_name = "Google", credentials_secret = "projects/my-project/secrets/google/versions/latest" }
      }
      static_policy = {
        default_redirect_uris = []
        clients = {
          app = { redirect_uris = ["https://app.example/callback"] }
        }
      }
    }
  }

  expect_failures = [var.truster_config]
}

run "zero_refresh_duration_is_invalid" {
  command = plan

  variables {
    truster_config = {
      secrets = {
        signing_key_name    = "projects/my-project/secrets/signing/versions/latest"
        encryption_key_name = "projects/my-project/secrets/encryption/versions/latest"
      }
      user_login_connectors = {
        google = { type = "google", display_name = "Google", credentials_secret = "projects/my-project/secrets/google/versions/latest" }
      }
      static_policy = {
        clients = {
          app = {
            redirect_uris = ["https://app.example/callback"]
            refresh_tokens = {
              enabled          = true
              session_idle_ttl = "0s"
            }
          }
        }
      }
    }
  }

  expect_failures = [var.truster_config]
}

run "equivalent_email_otp_duration_is_valid" {
  command = plan

  variables {
    truster_config = {
      secrets = { signing_key_name = "projects/my-project/secrets/signing/versions/latest" }
      user_login_connectors = {
        email = { type = "email", display_name = "Email" }
      }
      email = {
        otp_secret_name = "projects/my-project/secrets/otp/versions/latest"
        otp_ttl         = "60s"
        smtp = {
          host         = "smtp.example.com"
          port         = 587
          from_address = "auth@example.com"
        }
      }
      static_policy = { clients = { app = { redirect_uris = ["https://app.example/callback"] } } }
    }
  }
}

run "secret_references_require_full_version_names" {
  command = plan

  variables {
    truster_config = {
      secrets = {
        signing_key_name    = "signing"
        encryption_key_name = "projects/my-project/secrets/encryption/versions/latest"
      }
      user_login_connectors = {
        google = {
          type               = "google"
          display_name       = "Google"
          credentials_secret = "projects/my-project/secrets/google/versions/latest"
        }
      }
      static_policy = { clients = { app = { redirect_uris = ["https://app.example/callback"] } } }
    }
  }

  expect_failures = [google_compute_instance.main]
}
