# Writes a password to the try-it-locally container without storing it in
# state. Start the container with ../try-it-locally/up.sh first.

variable "db_password" {
  type      = string
  ephemeral = true
}

circuit "db" {
  hosts = { box = "127.0.0.1" }

  ssh {
    port             = 2222
    user             = "root"
    private_key_file = "../try-it-locally/id_ed25519"
    known_hosts_file = "../try-it-locally/known_hosts"
  }

  step "password" {
    file {
      path       = "/root/db-password"
      content_wo = var.db_password
    }
  }

  step "pgpass" {
    template {
      source      = "${path.module}/pgpass.tftpl"
      destination = "/root/.pgpass"
      vars        = { password = var.db_password }
      write_only  = true
    }
  }
}
