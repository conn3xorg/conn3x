variable "hosts" {
  type        = any
  description = "The hosts to configure: a map of names to addresses, or to host objects with an address and settings such as host_key."

  validation {
    condition     = can(keys(var.hosts)) && alltrue([for v in values(var.hosts) : can(tostring(v)) || can(tostring(v.address))])
    error_message = "hosts must be a map whose values are addresses, or objects with an address."
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

variable "app_package" {
  type        = string
  default     = "tree"
  description = "From the role's defaults/main.yml."
  validation {
    condition     = !strcontains(var.app_package, ",")
    error_message = "app_package names one package, so it can't have a comma; Ansible would read one as a list."
  }
}

variable "app_user" {
  type        = string
  default     = "app"
  description = "From the role's defaults/main.yml."
}

variable "app_port" {
  type        = number
  default     = 8080
  description = "From the role's defaults/main.yml."
}

variable "app_greeting" {
  type        = string
  default     = "Hello from a role"
  description = "From the role's defaults/main.yml."
}
