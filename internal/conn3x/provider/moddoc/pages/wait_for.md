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

Wait for a lock file to go away before an upgrade:

```hcl
step "unlocked" {
  wait_for {
    path  = "/var/lib/dpkg/lock-frontend"
    state = "absent"
  }
}
```

Wait for a line in a log:

```hcl
step "app_started" {
  wait_for {
    path     = "/var/log/app.log"
    contains = "^Started"
  }
}
```
Restart an app when its configuration changes, then wait for it to listen again before the next step:

```hcl
step "config" {
  file {
    path    = "/etc/myapp/config.yaml"
    content = "port: 3000\n"
  }
}

step "restart" {
  service_action {
    name     = "myapp"
    triggers = { config = conn3x_file.docs__config[each.key].revision }
  }
}

step "listening" {
  wait_for {
    port     = 3000
    triggers = { restart = conn3x_service_action.docs__restart[each.key].revision }
  }
}
```

<!-- reference -->
## How it works

**Waiting.** Conn3x checks on the host once a second until the path exists or something listens on the port, and fails the step if that takes longer than `timeout`. `timeout` takes a duration such as `"90s"` or `"10m"`, and defaults to `"5m"`.

**Going away.** With `state = "absent"`, the wait runs the other way: until the path is gone, or until nothing listens on the port. Ansible's `stopped` and `absent` are both this.

**File contents.** With `contains`, the path has to exist and match that regular expression. Conn3x reads the last MiB of the file once a second, so a line near the end of a busy log is found, and one more than a MiB back isn't. `^` and `$` match at the start and end of each line. The syntax is Go's, the same as `replace`'s `regexp`.

**Ports.** A port counts as ready when any process listens on it over TCP, on IPv4 or IPv6, on any address. Conn3x reads `/proc/net/tcp` and `/proc/net/tcp6`, so the host needs neither `ss` nor `netstat`.

**URLs.** Conn3x sends a `GET` to `url` once a second until the answer's status is in `status_codes`, `200` unless you say otherwise, and, with `body_contains`, its body holds that text. Redirects are followed first. The request is the host's, not this machine's: it goes through the SSH connection as a forwarded TCP connection that sshd opens on the host, so `127.0.0.1` is the host's loopback, a name resolves through the host's DNS, and the host needs no `curl` or `wget`. The host's sshd has to allow TCP forwarding, which it does by default; with `AllowTcpForwarding no`, the step fails with sshd's refusal instead of waiting. `https://` checks the certificate against this machine's trusted roots unless `skip_tls_verify` is true. A timeout says what the last answer was, such as `answered 503 Service Unavailable, not 200`. A proxy set on this machine isn't used.

**Reading.** Every plan checks again. If the path is gone, nothing listens on the port any more, or the URL stops answering as it should, the plan shows the step out of sync and the next apply waits again.

**Waiting again.** A check that passed at plan time isn't run again in the same apply. So a wait after a restart, which takes the port away only during the apply, needs `triggers`: set it to the restart step's revision, and the step waits again whenever that step runs.

**Validation.** Set exactly one of `path`, `port` and `url`. `path` must be absolute, `port` must be between 1 and 65535, and `state` is `"present"` (the default) or `"absent"`, and `"absent"` goes only with `path` or `port`, without `contains`. `contains` goes only with `path`, and `url` must start with `http://` or `https://` and name a host. A URL with a user or password in it is refused, since it would land in state. Changing `url` or its settings changes the step in place, and the next apply waits on the new ones.

## Removal

Deleting a `wait_for` step does nothing on the host.

## From Ansible

`conn3x convert ansible` turns `wait_for` tasks on the host itself into `wait_for` steps, carrying over `path` and `port`, `search_regex` with `path` as `contains`, and turning `timeout` in seconds into a duration such as `"300s"`. `delay` is dropped. `state: stopped` and `state: absent` become `state = "absent"`. A task that waits for another host, or with `state: drained`, which waits for a port's open connections to finish, stays a TODO, as does a `port` that isn't a whole number. `search_regex` on a `port`, which reads what the socket sends, stays a TODO, and so does a pattern that might match differently in Go than in Python, as for `replace`.
