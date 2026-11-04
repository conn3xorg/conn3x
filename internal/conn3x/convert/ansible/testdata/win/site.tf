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

circuit "shop_web_servers" {
  hosts = var.web_hosts

  ssh {
    user             = var.ssh_user
    private_key_file = var.ssh_private_key_file
  }

  # TODO(convert): Task "Install IIS" (site.yml line 7) uses register, which the converter can't translate yet.
  #   - name: Install IIS
  #     ansible.windows.win_feature:
  #       name: Web-Server
  #       include_management_tools: true
  #       state: present
  #     register: iis

  # TODO(convert): Task "Reboot if IIS asked for it" (site.yml line 14) uses when, which the converter can't translate yet.
  #   - name: Reboot if IIS asked for it
  #     ansible.windows.win_reboot:
  #     when: iis.reboot_required

  step "site_folder" {
    windows_directory {
      path = "C:\\inetpub\\shop"
    }
  }

  step "home_page" {
    windows_file {
      path    = "C:\\inetpub\\shop\\index.html"
      content = file("${path.module}/files/index.html")
    }
  }

  # TODO(convert): Task "App settings" (site.yml line 28) is a Jinja template; render it with templatefile() into a windows_file, whose line endings are written as they are, where win_template defaults to CRLF.
  #   - name: App settings
  #     ansible.windows.win_template:
  #       src: appsettings.json.j2
  #       dest: 'C:\inetpub\shop\appsettings.json'

  step "app_pool" {
    windows_iis_app_pool {
      name                    = "shop"
      managed_runtime_version = ""
      identity                = "NetworkService"
    }
  }

  # TODO(convert): Apply refuses a physical_path anyone but administrators can change, which a new folder with only inherited rules is, under C:\inetpub or at the top of C:. Give its windows_directory acl blocks: SYSTEM and Administrators full, IIS_IUSRS and IUSR read.
  step "site" {
    windows_iis_site {
      name          = "shop"
      physical_path = "C:\\inetpub\\shop"
      app_pool      = "shop"
      binding {
        port        = 8080
        host_header = "shop.example.com"
      }
    }
  }

  # Conn3x finds this rule by its ID, which is name; Ansible found it by its display name. If the rule Ansible made has another ID, delete it, or the two overlap.
  step "open_8080" {
    windows_firewall_rule {
      name        = "Shop HTTP"
      action      = "allow"
      protocol    = "tcp"
      local_ports = ["8080"]
      enabled     = true
    }
  }

  # TODO(convert): Task "Service account" (site.yml line 62) sets password_never_expires, which the converter can't translate yet.
  #   - name: Service account
  #     ansible.windows.win_user:
  #       name: shopsvc
  #       fullname: Shop service
  #       password: (secret left out; see the playbook)
  #       password_never_expires: true
  #       state: present

  step "operators_group" {
    windows_group {
      name        = "ShopOps"
      description = "Shop operators"
    }
  }

  step "operators_are_members" {
    windows_group {
      name    = "ShopOps"
      members = ["shopsvc"]
    }
  }

  step "world_wide_web_publishing_service" {
    windows_service {
      name       = "W3SVC"
      start_mode = "auto"
      state      = "running"
    }
  }

  # TODO(convert): Task "7-Zip" (site.yml line 89) has no SHA-256 for the package; write a windows_package with product_code, source or url, and sha256.
  #   - name: 7-Zip
  #     ansible.windows.win_package:
  #       path: https://www.7-zip.org/a/7z2409-x64.msi
  #       product_id: '{23170F69-40C1-2702-2409-000001000000}'
  #       state: present

  step "long_paths_on" {
    windows_registry_value {
      key  = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem"
      name = "LongPathsEnabled"
      type = "dword"
      data = "1"
    }
  }

  step "nightly_recycle" {
    windows_scheduled_task {
      name        = "RecycleShop"
      path        = "\\Shop\\"
      description = "Recycle the shop app pool"
      execute     = "C:\\Windows\\System32\\inetsrv\\appcmd.exe"
      arguments   = "recycle apppool /apppool.name:shop"
      user        = "SYSTEM"
      run_level   = "highest"
      trigger {
        type = "daily"
        at   = "2026-01-01T03:00:00"
      }
    }
  }

  # Review: this runs as PowerShell through windows_powershell. Check it does what the task did, and pass values through args.
  step "warm_the_cache" {
    windows_powershell {
      script  = "Invoke-WebRequest -UseBasicParsing -Headers @{ Host = 'shop.example.com' } http://localhost:8080/ | Out-Null\nSet-Content -Path C:\\inetpub\\shop\\warmed.txt -Value done\n"
      creates = "C:\\inetpub\\shop\\warmed.txt"
    }
  }

  # TODO(convert): Task "Telnet client on test boxes only" (site.yml line 124) uses when, which the converter can't translate yet.
  #   - name: Telnet client on test boxes only
  #     ansible.windows.win_feature:
  #       name: Telnet-Client
  #     when: env == 'test'

  step "wait_for_the_site" {
    windows_wait_for {
      port    = 8080
      timeout = "60s"
    }
  }
}
