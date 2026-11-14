Use `uri` to make one HTTP call from the host as part of a rollout: register it with a load balancer, tell a monitoring system a deploy happened, post to a chat webhook. It's `ansible.builtin.uri` for a call. To wait for an app to answer, use [`wait_for`](wait_for.md) with `url` instead.

## Example usage

Register the host once, with a token kept out of state:

```hcl
step "register" {
  uri {
    url          = "https://lb.example.com/api/backends"
    method       = "POST"
    headers      = { "Content-Type" = "application/json" }
    headers_wo   = { Authorization = "Bearer use-an-ephemeral-value-here" }
    body         = jsonencode({ host = "web1", port = 8080 })
    status_codes = [200, 201]
  }
}
```

Tell a webhook each time the app's version changes:

```hcl
step "announce" {
  uri {
    url      = "http://127.0.0.1:9000/hooks/deployed"
    method   = "POST"
    body     = "deployed"
    triggers = { version = "1.4.2" }
  }
}
```
<!-- reference -->
## How it works

**When it calls.** The first apply makes the call. After that, a change to any argument, or to `triggers`, makes it again. A refresh never calls, since a call leaves nothing on the host to read, and a plan with nothing changed shows nothing. `headers_wo` and `body_wo` can't be compared, since they're never stored, so put a version of the secret in `triggers` to call again when it changes.

**From the host.** The request goes through the SSH connection as a forwarded TCP connection that sshd opens on the host, as [`wait_for`](wait_for.md)'s `url` does. `127.0.0.1` is the host's loopback, a name resolves through the host's DNS, and the host needs no `curl`. Redirects are followed, `https://` checks the certificate unless `skip_tls_verify` is true, and no proxy set on this machine is used. A call can take 30 seconds.

**Success.** The step fails when the answer's status isn't in `status_codes`, `[200]` by default, and the error names the status. `status` and `response`, the first MiB of the body, are kept, and `response` is marked sensitive, since an API's answer often holds a token.

**Secrets.** `headers_wo` and `body_wo` reach the host's request and nowhere else: not the plan, not state. Set `body` or `body_wo`, not both.

## Removal

Deleting a `uri` step calls nothing. To undo what a call did, such as taking the host out of the load balancer, add a step that makes that call.
