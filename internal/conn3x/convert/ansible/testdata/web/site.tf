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

circuit "web_servers" {
  hosts = var.web_hosts

  ssh {
    user             = var.ssh_user
    private_key_file = var.ssh_private_key_file
    become           = true
  }

  step "install_nginx" {
    package {
      name = "nginx"
    }
  }

  # update_cache dropped: Conn3x refreshes the package lists when a package isn't found.
  step "install_tools_curl" {
    package {
      name = "curl"
    }
  }

  step "install_tools_git" {
    package {
      name = "git"
    }
  }

  step "write_the_home_page" {
    file {
      path    = "/usr/share/nginx/html/index.html"
      content = "<h1>Hello</h1>\n"
      mode    = "0644"
    }
    notify = [handler.reload_nginx]
  }

  step "ship_the_nginx_config" {
    file {
      path    = "/etc/nginx/nginx.conf"
      content = file("${path.module}/files/nginx.conf")
      mode    = "0644"
    }
    notify = [handler.restart_nginx]
  }

  step "listen_on_the_port" {
    line {
      path   = "/etc/nginx/conf.d/port.conf"
      line   = "listen 8080;"
      regexp = "^listen "
    }
  }

  step "start_nginx" {
    service {
      name    = "nginx"
      state   = "started"
      enabled = true
    }
  }

  step "allow_http" {
    firewalld {
      service = "http"
    }
  }

  # Conn3x keeps the job in /etc/cron.d rather than the user's crontab.
  step "nightly_cleanup" {
    cron {
      name     = "clean-tmp"
      schedule = "15 3 * * *"
      command  = "find /tmp -mtime +7 -delete"
    }
  }

  step "build_the_site" {
    command {
      command = "make -C /srv/site"
      creates = "/srv/site/public"
    }
  }

  # TODO(convert): Task "Users from a list" (site.yml line 64) uses loop, which the converter can't translate yet.
  #   - name: Users from a list
  #     user:
  #       name: "{{ item }}"
  #     loop: [alice, bob]

  # TODO(convert): Task "Say hello" (site.yml line 69) uses the debug module, which has no Conn3x equivalent yet.
  #   - name: Say hello
  #     debug:
  #       msg: hi

  handler "reload_nginx" {
    service {
      name   = "nginx"
      action = "reload"
    }
  }

  handler "restart_nginx" {
    service {
      name   = "nginx"
      action = "restart"
    }
  }
}
