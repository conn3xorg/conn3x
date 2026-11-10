terraform {
  required_providers {
    digitalocean = { source = "digitalocean/digitalocean" }
  }

  # State holds each droplet's SSH host private key, and whoever has one can
  # pass for that host. Keep state encrypted.
  encryption {
    key_provider "pbkdf2" "state" {
      passphrase = var.state_passphrase
    }
    method "aes_gcm" "state" {
      keys = key_provider.pbkdf2.state
    }
    state {
      method = method.aes_gcm.state
    }
    plan {
      method = method.aes_gcm.state
    }
  }
}

variable "state_passphrase" {
  type        = string
  sensitive   = true
  description = "Encrypts state and saved plans. At least 16 characters."
}

variable "ssh_key_id" {
  type        = string
  description = "ID or fingerprint of an SSH key already in your DigitalOcean account."
}

variable "admin_cidrs" {
  type        = list(string)
  description = "Who may reach SSH, such as [\"203.0.113.7/32\"]. Nothing else gets in."
}

variable "tags" {
  type    = list(string)
  default = []
}

locals {
  servers = toset(["app-1", "app-2", "app-3"])
}

# Each server's SSH host key, made here and installed by cloud-init,
# so Conn3x can check it on the very first connection.
#
# DigitalOcean has one way to hand a new droplet anything: user data. The
# droplet's metadata service serves it back, without a login, to any process
# on the droplet that asks, for as long as the droplet lives. So the private
# key below is readable by every local user until the "metadata" steps in the
# circuit close that off.
resource "tls_private_key" "host" {
  for_each  = local.servers
  algorithm = "ED25519"
}

resource "digitalocean_droplet" "app" {
  for_each = local.servers
  name     = each.key
  image    = "rockylinux-10-x64"
  region   = "nyc3"
  size     = "s-1vcpu-1gb"
  ssh_keys = [var.ssh_key_id]
  tags     = var.tags

  user_data = "#cloud-config\n${yamlencode({
    ssh_deletekeys = true
    ssh_keys = {
      ed25519_private = tls_private_key.host[each.key].private_key_openssh
      ed25519_public  = tls_private_key.host[each.key].public_key_openssh
    }
  })}"
}

# SSH from you and nobody else. Without this the droplets take root logins
# from the whole internet. Outbound stays open, for packages.
resource "digitalocean_firewall" "app" {
  name        = "conn3x-example-app"
  droplet_ids = [for d in digitalocean_droplet.app : d.id]
  tags        = var.tags

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = var.admin_cidrs
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

circuit "app" {
  hosts = {
    for name, d in digitalocean_droplet.app : name => {
      address  = d.ipv4_address
      host_key = tls_private_key.host[name].public_key_openssh
    }
  }

  ssh {
    user             = "root"
    private_key_file = "~/.ssh/id_ed25519"
    timeout          = "5m"
  }

  # Only root may ask the metadata service for anything from here on, so the
  # deploy user can't read the host key out of the user data. These come
  # before the first account that isn't root. Leave them out if you run
  # DigitalOcean's monitoring agent, which asks as its own user.
  step "nftables" {
    package {
      name = "nftables"
    }
  }

  step "metadata_rule" {
    file {
      path     = "/etc/nftables/conn3x-metadata.nft"
      validate = "nft -c -f %s"
      content  = <<-NFT
        table inet conn3x_metadata
        delete table inet conn3x_metadata
        table inet conn3x_metadata {
          chain output {
            type filter hook output priority 0; policy accept;
            ip daddr 169.254.169.254 meta skuid != 0 reject
          }
        }
      NFT
    }
  }

  step "metadata_rule_at_boot" {
    line {
      path = "/etc/sysconfig/nftables.conf"
      line = "include \"/etc/nftables/conn3x-metadata.nft\""
    }
  }

  # Starting the service loads the rule now; enabling it loads it at boot.
  step "metadata_root_only" {
    service {
      name    = "nftables"
      state   = "started"
      enabled = true
    }
  }

  step "deploy_user" {
    user {
      name  = "deploy"
      shell = "/bin/bash"
    }
  }

  step "deploy_key" {
    authorized_key {
      user = "deploy"
      key  = file("${path.module}/deploy.pub")
    }
  }
}

output "addresses" {
  value = { for name, d in digitalocean_droplet.app : name => d.ipv4_address }
}
