# Converted from the Ansible role famwhen by conn3x convert ansible.
# Search for TODO(convert) to find what still needs a person.

circuit "famwhen" {
  hosts = var.hosts

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  # Task "Include OS-specific variables." (tasks/main.yml line 2) loads vars/<family>.yml: the steps below that use those values look them up by each host's family.

  step "debian_only" {
    when = local.os_family[each.key] == "debian"
    file {
      path    = "/etc/famwhen-debian"
      content = "debian\n"
    }
  }

  step "red_hat_only" {
    when = local.os_family[each.key] == "redhat"
    directory {
      path = "/srv/famwhen-redhat"
    }
  }

  # TODO(convert): Task "Everywhere." (tasks/main.yml line 17) uses when on the Suse_never_named family, which Conn3x doesn't run on; Conn3x hosts are Debian or Red Hat family.
  #   - name: Everywhere.
  #     copy:
  #       dest: /etc/famwhen-all
  #       content: "all\n"
  #     when: ansible_facts.os_family != "Suse_never_named"
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
