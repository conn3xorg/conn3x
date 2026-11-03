**Experimental.** Windows support is new, and this module may change between releases.

Use `windows_iis_site` to serve a folder from IIS on the ports and host names you choose. It needs IIS installed and, if you name one, its application pool in place first.

## Example usage

```hcl
step "site" {
  windows_iis_site {
    name          = "shop"
    physical_path = "C:\\sites\\shop"
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

`physical_path` must be a folder on a local drive. Conn3x doesn't make it or check who can write to it: anyone who can change the files there can change what the site serves, and runs code as the pool's identity when the site runs code. With `app_pool` unset, a new site gets IIS's default pool and an existing site keeps its own.

On a host without IIS, a site reads as missing rather than failing.

## Removal

By default, deleting a `windows_iis_site` step deletes the site, and its files stay. With `on_remove = "forget"` the site stays.
