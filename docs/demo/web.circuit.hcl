circuit "web" {
  hosts = { web1 = "127.0.0.1" }

  ssh {
    port             = 2222
    user             = "root"
    private_key_file = "./id_ed25519"
    known_hosts_file = "./known_hosts"
  }

  step "motd" {
    file {
      path    = "/etc/motd"
      content = "Welcome to ${each.key}, managed by Conn3x\n"
    }
  }
}
