Use `fetch` to bring a file back from a host to the machine running Conn3x: the CA certificate a step just generated, a cluster's join token, a log you want to read. It's Ansible's `fetch`, and it runs at apply, so it picks up a file the same apply wrote.

## Example usage

Bring each node's join token back, one file per host:

```hcl
step "join_token" {
  fetch {
    src  = "/var/lib/rancher/k3s/server/node-token"
    dest = "tokens/${each.key}"
  }
}
```

A log that may not be there yet:

```hcl
step "install_log" {
  fetch {
    src             = "/var/log/app/install.log"
    dest            = "logs/${each.key}-install.log"
    fail_on_missing = false
  }
}
```
<!-- reference -->
## How it works

**Where the copy goes.** `dest` is a file name on the machine running Conn3x, relative to the directory you run it in. A step runs on every host in the circuit, so put `${each.key}` in `dest`, or every host writes the same file and each apply swaps one for another.

**Nothing in state.** State keeps whether the copy matched at the last refresh, never the file's content, so fetching a private key or a token doesn't put it in state. The copy is written owner-only, `0600`, in a directory made `0700` when it's missing, since what's fetched is often a secret. It goes in through a file beside it, so nothing ever reads half a copy.

**Reading.** On every plan, Conn3x reads `src` on the host and `dest` here. When they differ, or `dest` is missing, the plan shows an update. Editing or deleting the copy by hand brings it back on the next apply.

**A file an earlier step writes.** In a circuit, a plan that changes any step before this one on the host reads `src` again at apply time. So a certificate a `command` step generates comes back in the same apply, not the next one.

**A missing file.** `src` missing fails the apply, saying so. With `fail_on_missing = false`, the step leaves `dest` as it is and shows as in sync.

## Removal

`on_remove = "forget"`, the default, leaves the copy. `on_remove = "delete"` deletes `dest`. The host's file is never touched.

## From Ansible

`conn3x convert ansible` turns `ansible.builtin.fetch` tasks into `fetch` steps. Without `flat`, Ansible writes the copy at `dest/<host>/<src>`, and the converted `dest` is the same layout with `${each.key}`. With `flat: true`, `dest` carries over, and the step gets a note that every host writes that one file. `fail_on_missing` carries over, and `validate_checksum` is dropped: the step always compares the two copies. A `src` or `dest` built from a variable, and a relative `src`, stay TODOs.
