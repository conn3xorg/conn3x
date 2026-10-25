terraform {
  required_providers {
    digitalocean = { source = "digitalocean/digitalocean" }
  }
}

variable "ssh_key_id" {
  type        = string
  description = "ID or fingerprint of an SSH key already in your DigitalOcean account."
}

locals {
  servers = toset(["app-1", "app-2", "app-3"])
}

# Each server's SSH host key, made here and installed by cloud-init,
# so Conn3x can check it on the very first connection.
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

  user_data = "#cloud-config\n${yamlencode({
    ssh_deletekeys = true
    ssh_keys = {
      ed25519_private = tls_private_key.host[each.key].private_key_openssh
      ed25519_public  = tls_private_key.host[each.key].public_key_openssh
    }
  })}"
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
