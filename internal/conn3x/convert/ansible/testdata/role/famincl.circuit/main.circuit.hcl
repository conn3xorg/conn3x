# Converted from the Ansible role famincl by conn3x convert ansible.
# Search for TODO(convert) to find what still needs a person.

circuit "famincl" {
  hosts = var.hosts

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  step "debian_setup" {
    when = local.os_family[each.key] == "debian"
    file {
      path    = "/etc/famincl-debian"
      content = "debian\n"
    }
  }

  step "red_hat_setup" {
    when = local.os_family[each.key] == "redhat"
    file {
      path    = "/etc/famincl-redhat"
      content = "redhat\n"
    }
  }

  step "debian_extra" {
    when = local.os_family[each.key] == "debian"
    file {
      path    = "/etc/famincl-extra"
      content = "extra\n"
    }
  }

  # TODO(convert): This task (tasks/main.yml line 8) includes setup-Archlinux.yml with a when no Debian or Red Hat family host meets, so none of it would run.
  #   - include_tasks: setup-Archlinux.yml
  #     when: ansible_facts.os_family == 'Archlinux'
}

# Each host's OS family, for the values the role loads per family. A host
# object's os, such as "ubuntu", is used when given, as for a host this
# plan creates; otherwise its facts are read.
data "conn3x_host" "facts" {
  for_each = var.hosts

  ssh {
    host             = try(each.value.address, each.value)
    port             = try(each.value.port, var.ssh_port)
    user             = try(each.value.user, var.ssh_user)
    host_key         = try(each.value.host_key, null)
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  lifecycle {
    postcondition {
      condition     = try(local.os_families[each.value.os], self.os_family) == self.os_family
      error_message = "Host ${each.key} is ${self.os_family} family, not what its os says."
    }
  }
}

locals {
  os_families = {
    debian = "debian", ubuntu = "debian",
    rhel   = "redhat", rocky = "redhat", almalinux = "redhat", fedora = "redhat",
  }
  os_family = { for name, h in var.hosts : name => try(local.os_families[h.os], data.conn3x_host.facts[name].os_family) }
}
