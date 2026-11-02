**Experimental.** Windows support is new, and this module may change between releases.

Use `windows_wait_for` to pause a circuit until a path exists, a service is running or a TCP port is listening on a Windows host. It keeps trying through a reboot, so it's the natural step to follow `windows_reboot`.

## Example usage

```hcl
step "web_up" {
  windows_wait_for {
    service = "W3SVC"
    timeout = "10m"
  }
}
```

```hcl
step "app_listening" {
  windows_wait_for {
    port = 8080
  }
}
```

```hcl
step "app_ready" {
  windows_wait_for {
    path    = "C:\\app\\ready"
    timeout = "1m"
  }
}
```
<!-- reference -->
## How it works

**Waiting.** Conn3x checks every two seconds, and fails the step if it isn't ready after `timeout`, which defaults to `"5m"`. Each check starts PowerShell in a new session. If the host can't be reached yet, that counts as not ready.

**Reading.** Every plan checks again. If the path is gone, the service stopped or nothing listens on the port any more, the plan shows the step out of sync and the next apply waits again.

**Validation.** Set exactly one of `path`, `service` and `port`. `path` must be a drive-letter or UNC path.

## Removal

Deleting a `windows_wait_for` step does nothing on the host.
