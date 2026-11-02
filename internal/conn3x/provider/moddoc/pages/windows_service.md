**Experimental.** Windows support is new, and this module may change between releases.

Use `windows_service` to say how an existing service starts and whether it's running. Conn3x doesn't create services here.

## Example usage

```hcl
step "web_running" {
  windows_service {
    name       = "W3SVC"
    start_mode = "auto"
    state      = "running"
  }
}
```

```hcl
step "no_print_spooler" {
  windows_service {
    name       = "Spooler"
    start_mode = "disabled"
    state      = "stopped"
  }
}
```
<!-- reference -->
## How it works

Use the service's name, not its display name, which changes with the display language. Stopping a service that others depend on fails with Windows' message: stop those first. A service that stops right after starting shows as an error at apply, not a success.

Be careful with `sshd`. Stopping or disabling it cuts Conn3x off from the host.

## Removal

Deleting a `windows_service` step leaves the service as it is.
