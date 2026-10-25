circuit "try" {
  hosts = { box = "127.0.0.1" }

  ssh {
    port             = 2222
    user             = "root"
    private_key_file = "./id_ed25519"
    known_hosts_file = "./known_hosts"
  }

  step "tools" {
    package {
      name = "tree"
    }
  }

  step "deploy_user" {
    user {
      name  = "deploy"
      shell = "/bin/bash"
    }
  }

  step "motd" {
    file {
      path    = "/etc/motd"
      content = "Hello from ${each.key}, set up by Conn3x.\n"
    }
  }
}
