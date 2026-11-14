# Converted from site.yml by conn3x convert ansible.
# Search for TODO(convert) to find what still needs a person.

variable "emea_dc_hosts" {
  type        = map(string)
  description = "Hosts in the Ansible group \"emea_dc\", as name = address."
}

variable "ssh_user" {
  type        = string
  description = "User Conn3x logs in as."
}

variable "ssh_private_key_file" {
  type        = string
  description = "Private key Conn3x logs in with."
}

circuit "emea_child_domain" {
  hosts = var.emea_dc_hosts

  ssh {
    user             = var.ssh_user
    private_key_file = var.ssh_private_key_file
  }

  # TODO(convert): Set password_wo and safe_mode_password_wo from ephemeral variables. The task's passwords aren't copied here.
  step "make_emea_lab_example_com_domain" {
    windows_ad_domain {
      domain_name   = "emea.lab.example.com"
      username      = "admin@lab.example.com"
      database_path = "D:\\NTDS"
    }
  }

  step "make_emea_lab_example_com_reboot" {
    windows_reboot {
      only_if_pending = true
      timeout         = "1800s"
    }
  }

  step "make_emea_lab_example_com_adws" {
    windows_wait_for {
      port = 9389
    }
  }

  # TODO(convert): Set password_wo and safe_mode_password_wo from ephemeral variables. The task's passwords aren't copied here.
  step "same_as_a_new_tree" {
    windows_ad_domain {
      domain_name        = "corp.example.net"
      domain_type        = "tree"
      parent_domain_name = "lab.example.com"
      username           = "admin@lab.example.com"
    }
  }
}
