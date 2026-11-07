# Converted from the Ansible role app by conn3x convert ansible.
# Search for TODO(convert) to find what still needs a person.

circuit "app" {
  hosts = var.hosts

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  step "install_the_package" {
    package {
      name = var.app_package
    }
  }

  step "service_account" {
    user {
      name  = var.app_user
      shell = "/bin/sh"
    }
  }

  step "app_directory" {
    directory {
      path  = "/opt/app"
      mode  = "0750"
      owner = var.app_user
    }
  }

  step "app_config" {
    template {
      source      = "${path.module}/templates/app.conf.tftpl"
      destination = "/opt/app/app.conf"
      vars = {
        app_dir      = "/opt/app"
        app_greeting = var.app_greeting
        app_port     = var.app_port
        app_user     = var.app_user
      }
      mode  = "0640"
      owner = var.app_user
    }
    notify = [handler.restart_app]
  }

  step "app_unit" {
    file {
      path    = "/etc/systemd/system/app.service"
      content = file("${path.module}/files/app.service")
      mode    = "0644"
    }
    notify = [handler.restart_app]
  }

  step "login_banner" {
    line {
      path   = "/etc/issue.net"
      create = true
      line   = var.app_greeting
    }
  }

  step "start_the_app" {
    service {
      name    = "app"
      state   = "started"
      enabled = true
    }
  }

  handler "restart_app" {
    service {
      name   = "app"
      action = "restart"
    }
  }
}
