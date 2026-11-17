# Report-only checks modelled on CIS benchmark items. Each data source runs
# a read-only command on every host when you plan, and each check block
# names the hosts that break the rule. Nothing on a host changes.

variable "hosts" {
  type    = map(string)
  default = { box = "127.0.0.1" }
}

# Root can't log in over SSH. sshd -T prints the settings sshd really uses,
# after every Include and Match.
data "conn3x_command" "root_login" {
  for_each = var.hosts
  command  = "sshd -T | grep -i '^permitrootlogin '"

  ssh {
    host             = each.value
    port             = 2222
    user             = "root"
    private_key_file = "../try-it-locally/id_ed25519"
    known_hosts_file = "../try-it-locally/known_hosts"
  }
}

# New passwords expire within a year.
data "conn3x_command" "pass_max_days" {
  for_each = var.hosts
  command  = "awk '$1 == \"PASS_MAX_DAYS\" { print $2 }' /etc/login.defs"

  ssh {
    host             = each.value
    port             = 2222
    user             = "root"
    private_key_file = "../try-it-locally/id_ed25519"
    known_hosts_file = "../try-it-locally/known_hosts"
  }
}

# No world-writable files on the root filesystem.
data "conn3x_command" "world_writable" {
  for_each = var.hosts
  command  = "find / -xdev -type f -perm -0002 2>/dev/null | head -n 20"

  ssh {
    host             = each.value
    port             = 2222
    user             = "root"
    private_key_file = "../try-it-locally/id_ed25519"
    known_hosts_file = "../try-it-locally/known_hosts"
  }
}

locals {
  # The output is marked sensitive in case it holds a secret. These lines
  # are settings and file names, so reading them is safe.
  root_login = [for h, d in data.conn3x_command.root_login : h if trimspace(nonsensitive(d.stdout)) != "permitrootlogin no"]
  pass_age   = [for h, d in data.conn3x_command.pass_max_days : h if tonumber(trimspace(nonsensitive(d.stdout))) > 365]
  writable = {
    for h, d in data.conn3x_command.world_writable :
    h => split("\n", trimspace(nonsensitive(d.stdout))) if trimspace(nonsensitive(d.stdout)) != ""
  }
}

check "ssh_root_login" {
  assert {
    condition     = length(local.root_login) == 0
    error_message = "Root can log in over SSH on ${join(", ", local.root_login)}."
  }
}

check "password_max_age" {
  assert {
    condition     = length(local.pass_age) == 0
    error_message = "PASS_MAX_DAYS is over 365 on ${join(", ", local.pass_age)}."
  }
}

check "world_writable_files" {
  assert {
    condition     = length(local.writable) == 0
    error_message = join("; ", [for h, files in local.writable : "${h}: ${join(", ", files)}"])
  }
}
