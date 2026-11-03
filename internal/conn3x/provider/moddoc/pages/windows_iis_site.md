**Experimental.** Windows support is new, and this module may change between releases.

Use `windows_iis_site` to serve a folder from IIS on the ports and host names you choose. It needs IIS installed, the folder made admin-only, and, if you name one, its application pool in place first.

## Example usage

```hcl
# Admin-only from the moment it exists. IIS_IUSRS (the pools) and IUSR
# (anonymous visitors) may only read.
step "site_folder" {
  windows_directory {
    path = "C:\\inetpub\\shop"

    acl {
      principal = "S-1-5-32-544"
      rights    = ["FullControl"]
    }
    acl {
      principal = "S-1-5-18"
      rights    = ["FullControl"]
    }
    acl {
      principal = "S-1-5-32-568"
      rights    = ["ReadAndExecute"]
    }
    acl {
      principal = "S-1-5-17"
      rights    = ["ReadAndExecute"]
    }
  }
}

step "site" {
  windows_iis_site {
    name          = "shop"
    physical_path = "C:\\inetpub\\shop"
    app_pool      = "shop"

    binding {
      port        = 80
      host_header = "shop.example.com"
    }
  }
}

step "http_in" {
  windows_firewall_rule {
    name        = "shop http"
    protocol    = "tcp"
    local_ports = ["80"]
  }
}
```
<!-- reference -->
## How it works

The `binding` blocks are all of the site's bindings: one added by hand, https included, shows as drift, and the next apply removes it. Only http bindings are supported for now. A binding's `ip` defaults to `*`, every address, and with no `host_header` the site answers any host name. Two sites can't both start on the same address, port and host name: on a fresh install, `Default Web Site` already has `*:80`, so give your site a `host_header`, another port, or stop that site first.

`state` defaults to `started` and also sets whether the site starts with IIS. If the site can't start, apply says why, which is most often a binding another site already has.

`physical_path` must be a folder on a local drive that already exists, and only administrators may change it or any folder on the way to it. Apply refuses it otherwise, whatever the pool's identity: whoever can drop a page or a `web.config` there runs code as the pool, and every built-in pool identity can impersonate its way to SYSTEM. The check covers the folder's own access rules, including what it hands down to everything inside, but not files or subfolders inside it that carry rules of their own. Before this module leaves experimental, it will also scan for `web.config` files and subfolders with their own rules. With `app_pool` unset, a new site gets IIS's default pool and an existing site keeps its own.

Serving files needs IIS's static content role service, `Web-Static-Content`. A plain `Web-Server` install includes it; without it, IIS answers 200 with an empty page. A `windows_feature` step for it makes sure.

On a host without IIS, a site reads as missing rather than failing.

## Removal

By default, deleting a `windows_iis_site` step deletes the site, and its files stay. With `on_remove = "forget"` the site stays.
