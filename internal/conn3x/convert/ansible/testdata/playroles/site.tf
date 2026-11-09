# Converted from site.yml by conn3x convert ansible.
# Search for TODO(convert) to find what still needs a person.

variable "web_hosts" {
  type        = map(string)
  description = "Hosts in the Ansible group \"web\", as name = address."
}

variable "ssh_user" {
  type        = string
  description = "User Conn3x logs in as."
}

variable "ssh_private_key_file" {
  type        = string
  description = "Private key Conn3x logs in with."
}

circuit "web" {
  hosts = var.web_hosts

  ssh {
    user             = var.ssh_user
    private_key_file = var.ssh_private_key_file
    become           = true
  }

  step "install_curl" {
    package {
      name = "curl"
    }
  }
}

module "web" {
  source = "./circuit-web"

  hosts                = var.web_hosts
  ssh_user             = var.ssh_user
  ssh_private_key_file = var.ssh_private_key_file
  ssh_become           = true

  web_port = 8080

  depends_on = [conn3x_package.web__install_curl]
}

circuit "web_2" {
  hosts = var.web_hosts

  ssh {
    user             = var.ssh_user
    private_key_file = var.ssh_private_key_file
    become           = true
  }

  step "write_the_motd" {
    file {
      path    = "/etc/motd"
      content = "Managed by Conn3x\n"
    }
    depends_on = [module.web]
  }
}

module "web_2" {
  source = "./circuit-web"

  hosts                = var.web_hosts
  ssh_user             = var.ssh_user
  ssh_private_key_file = var.ssh_private_key_file
  ssh_become           = true

  # TODO(convert): Task "Second site" (site.yml line 16) passes web_extra, which circuit-web has no variable for, because the role fixes it in vars/ or its default isn't a plain value; set it in the circuit by hand.
  #   - name: Second site
  #     include_role:
  #       name: web
  #     vars:
  #       web_port: 9090
  #       web_extra: x

  web_port = 9090

  depends_on = [conn3x_file.web_2__write_the_motd]
}

circuit "web_3" {
  hosts = var.web_hosts

  ssh {
    user             = var.ssh_user
    private_key_file = var.ssh_private_key_file
    become           = true
  }

  # TODO(convert): Task "Something else" (site.yml line 22) runs the role missing, which isn't at roles/missing beside the playbook; install it there, as with ansible-galaxy role install -p roles, and convert again.
  #   - name: Something else
  #     include_role:
  #       name: missing
}
