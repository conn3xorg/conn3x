variable "hosts" {
  type        = any
  description = "The hosts to configure: a map of names to addresses, or to host objects with an address and settings such as host_key, and os (debian, ubuntu, rocky, almalinux, rhel or fedora) for a host whose facts can't be read yet."

  validation {
    condition     = can(keys(var.hosts)) && alltrue([for v in values(var.hosts) : can(tostring(v)) || can(tostring(v.address))])
    error_message = "hosts must be a map whose values are addresses, or objects with an address."
  }

  validation {
    condition     = alltrue([for h in var.hosts : contains(["debian", "ubuntu", "rocky", "almalinux", "rhel", "fedora"], try(h.os, "debian"))])
    error_message = "A host object's os must be one of debian, ubuntu, rocky, almalinux, rhel or fedora. CentOS Linux reached end of life on 30 June 2024: use Rocky Linux."
  }
}

variable "ssh_user" {
  type        = string
  default     = "root"
  description = "The user to log in as."
}

variable "ssh_port" {
  type        = number
  default     = 22
  description = "The SSH port."
}

variable "ssh_private_key_file" {
  type        = string
  default     = null
  description = "Path to a private key file. When null, Conn3x uses the SSH agent."
}

variable "ssh_known_hosts_file" {
  type        = string
  default     = null
  description = "The known_hosts file to check host keys against. When null, Conn3x uses ~/.ssh/known_hosts."
}

variable "ssh_become" {
  type        = bool
  default     = false
  description = "Run every command as root through sudo. Set this when ssh_user isn't root."
}

# Default "mixed_conf" (defaults/main.yml line 4) is a Jinja expression, which the converter can't carry over as a variable yet. Tasks that use it are marked TODO(convert).

# Default "mixed_umask" (defaults/main.yml line 6) is a value YAML could read as a number or a date, which the converter can't carry over as a variable yet. Tasks that use it are marked TODO(convert).

variable "mixed_enabled" {
  type        = bool
  default     = true
  description = "From the role's defaults/main.yml."
}

variable "mixed_mode" {
  type        = string
  default     = "0644"
  description = "From the role's defaults/main.yml."
}

variable "mixed_conf_dir" {
  type        = string
  default     = "/etc/mixed"
  description = "From the role's defaults/main.yml."
}

# Default "mixed_ports" (defaults/main.yml line 5) is a list, which the converter carries over as a variable only for a loop over it. Tasks that use it are marked TODO(convert).
