Use `wait_for` to pause a circuit until a path exists or a TCP port is listening on the host, such as a service's socket after it starts. The step after it runs only once the wait is over.

## Example usage

Wait for a service to listen on a port:

```hcl
step "postgres_up" {
  wait_for {
    port = 5432
  }
}
```

Wait for a file, for up to a minute:

```hcl
step "app_ready" {
  wait_for {
    path    = "/run/app/ready"
    timeout = "1m"
  }
}
```
<!-- reference -->
## How it works

**Waiting.** Conn3x checks on the host once a second until the path exists or something listens on the port, and fails the step if that takes longer than `timeout`. `timeout` takes a duration such as `"90s"` or `"10m"`, and defaults to `"5m"`.

**Ports.** A port counts as ready when any process listens on it over TCP, on IPv4 or IPv6, on any address. Conn3x reads `/proc/net/tcp` and `/proc/net/tcp6`, so the host needs neither `ss` nor `netstat`.

**Reading.** Every plan checks again. If the path is gone or nothing listens on the port any more, the plan shows the step out of sync and the next apply waits again.

**Validation.** Set exactly one of `path` and `port`. `path` must be absolute, and `port` must be between 1 and 65535.

## Removal

Deleting a `wait_for` step does nothing on the host.

## From Ansible

`conn3x convert ansible` turns `wait_for` tasks on the host itself into `wait_for` steps, carrying over `path` and `port`, and turning `timeout` in seconds into a duration such as `"300s"`. `delay` is dropped. A task that waits for another host, or for a state other than `started` or `present`, stays a TODO.
