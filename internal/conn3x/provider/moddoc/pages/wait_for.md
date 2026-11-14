Use `wait_for` to pause a circuit until a path exists, a TCP port is listening, or a URL answers on the host, such as a service's socket after it starts or an app's health check after a deploy. The step after it runs only once the wait is over.

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

Wait for an app's health check to say so, from the host itself:

```hcl
step "app_healthy" {
  wait_for {
    url           = "http://127.0.0.1:8080/healthz"
    body_contains = "ok"
    timeout       = "2m"
  }
}
```
<!-- reference -->
## How it works

**Waiting.** Conn3x checks on the host once a second until the path exists or something listens on the port, and fails the step if that takes longer than `timeout`. `timeout` takes a duration such as `"90s"` or `"10m"`, and defaults to `"5m"`.

**Ports.** A port counts as ready when any process listens on it over TCP, on IPv4 or IPv6, on any address. Conn3x reads `/proc/net/tcp` and `/proc/net/tcp6`, so the host needs neither `ss` nor `netstat`.

**URLs.** Conn3x sends a `GET` to `url` once a second until the answer's status is in `status_codes`, `200` unless you say otherwise, and, with `body_contains`, its body holds that text. Redirects are followed first. The request is the host's, not this machine's: it goes through the SSH connection as a forwarded TCP connection that sshd opens on the host, so `127.0.0.1` is the host's loopback, a name resolves through the host's DNS, and the host needs no `curl` or `wget`. The host's sshd has to allow TCP forwarding, which it does by default; with `AllowTcpForwarding no`, the step fails with sshd's refusal instead of waiting. `https://` checks the certificate against this machine's trusted roots unless `skip_tls_verify` is true. A timeout says what the last answer was, such as `answered 503 Service Unavailable, not 200`. A proxy set on this machine isn't used.

**Reading.** Every plan checks again. If the path is gone, nothing listens on the port any more, or the URL stops answering as it should, the plan shows the step out of sync and the next apply waits again.

**Validation.** Set exactly one of `path`, `port` and `url`. `path` must be absolute, `port` must be between 1 and 65535, and `url` must start with `http://` or `https://` and name a host. A URL with a user or password in it is refused, since it would land in state. Changing `url` or its settings changes the step in place, and the next apply waits on the new ones.

## Removal

Deleting a `wait_for` step does nothing on the host.

## From Ansible

`conn3x convert ansible` turns `wait_for` tasks on the host itself into `wait_for` steps, carrying over `path` and `port`, and turning `timeout` in seconds into a duration such as `"300s"`. `delay` is dropped. A task that waits for another host, or for a state other than `started` or `present`, stays a TODO, as does a `port` that isn't a whole number.
