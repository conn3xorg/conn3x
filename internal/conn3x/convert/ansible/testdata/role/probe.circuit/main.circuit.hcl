# Converted from the Ansible role probe by conn3x convert ansible.
# Search for TODO(convert) to find what still needs a person.

circuit "probe" {
  hosts = var.hosts

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  # Task "Check for the marker." (tasks/main.yml line 2) probes each host: data.conn3x_command.marker, after the circuit, runs it at plan time, and the steps whose when read marker test its result.

  # Task "Read the kernel name." (tasks/main.yml line 9) probes each host: data.conn3x_command.kernel, after the circuit, runs it at plan time, and the steps whose when read kernel test its result.

  # TODO(convert): Set mode if this file isn't meant to be 0644. The task set none, so Ansible left a file that was already there as it was; this step sets 0644.
  step "say_the_marker_was_missing" {
    when = data.conn3x_command.marker[each.key].exit_code != 0
    file {
      path    = "/etc/probe-missing"
      content = "missing\n"
    }
  }

  # TODO(convert): Set mode if this file isn't meant to be 0644. The task set none, so Ansible left a file that was already there as it was; this step sets 0644.
  step "say_the_marker_was_there" {
    when = data.conn3x_command.marker[each.key].exit_code == 0
    file {
      path    = "/etc/probe-found"
      content = "found\n"
    }
  }

  # TODO(convert): Set mode if this file isn't meant to be 0644. The task set none, so Ansible left a file that was already there as it was; this step sets 0644.
  step "linux_only" {
    when = nonsensitive(chomp(data.conn3x_command.kernel[each.key].stdout) == "Linux")
    file {
      path    = "/etc/probe-linux"
      content = "linux\n"
    }
  }
}

# Task "Check for the marker." (tasks/main.yml line 2) probes each host at plan time,
# as Ansible ran it before any task had changed the host. The steps whose
# when read marker test its result.
data "conn3x_command" "marker" {
  for_each = var.hosts
  command  = "test -e /etc/probe-marker"

  ssh {
    host             = try(each.value.address, each.value)
    port             = try(each.value.port, var.ssh_port)
    user             = try(each.value.user, var.ssh_user)
    host_key         = try(each.value.host_key, null)
    container        = try(each.value.container, null)
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }
}

# Task "Read the kernel name." (tasks/main.yml line 9) probes each host at plan time,
# as Ansible ran it before any task had changed the host. The steps whose
# when read kernel test its result.
data "conn3x_command" "kernel" {
  for_each = var.hosts
  command  = "uname -s"

  ssh {
    host             = try(each.value.address, each.value)
    port             = try(each.value.port, var.ssh_port)
    user             = try(each.value.user, var.ssh_user)
    host_key         = try(each.value.host_key, null)
    container        = try(each.value.container, null)
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  lifecycle {
    postcondition {
      condition     = self.exit_code == 0
      error_message = "kernel exited ${self.exit_code} on host ${each.key}, where Ansible would have stopped the play."
    }
  }
}
