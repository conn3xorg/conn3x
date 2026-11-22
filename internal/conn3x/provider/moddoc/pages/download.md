Use `download` to fetch a file from a URL onto a host and keep it only if its SHA-256 checksum matches. The host downloads the file itself, so it needs access to the URL.

## Example usage

Download a release:

```hcl
step "node_exporter_tarball" {
  download {
    url    = "https://github.com/prometheus/node_exporter/releases/download/v1.8.2/node_exporter-1.8.2.linux-amd64.tar.gz"
    dest   = "/opt/downloads/node_exporter-1.8.2.linux-amd64.tar.gz"
    sha256 = "6809dd0b3ec45fd6e992c19071d6b5253aed3ead7bf0686885a51d85c6643c66"
  }
}
```

Download and unpack it, with an [`archive`](/modules/archive) step that runs after:

```hcl
step "node_exporter_tarball" {
  download {
    url    = "https://github.com/prometheus/node_exporter/releases/download/v1.8.2/node_exporter-1.8.2.linux-amd64.tar.gz"
    dest   = "/opt/downloads/node_exporter-1.8.2.linux-amd64.tar.gz"
    sha256 = "6809dd0b3ec45fd6e992c19071d6b5253aed3ead7bf0686885a51d85c6643c66"
  }
}

step "node_exporter" {
  archive {
    src     = "/opt/downloads/node_exporter-1.8.2.linux-amd64.tar.gz"
    dest    = "/opt"
    creates = "/opt/node_exporter-1.8.2.linux-amd64/node_exporter"
  }
}
```
<!-- reference -->
## How it works

**Reading.** Every plan computes the SHA-256 of the file at `dest` with `sha256sum`. The step is in sync when the file is there and its checksum matches `sha256`. A missing file, or one with a different checksum, plans a new download. Changing `url`, `sha256`, `mode`, `owner` or `group` also plans one.

**Downloading.** Conn3x creates the parent directories of `dest`, then downloads to a temporary file beside it with `curl`, or with `wget` when `curl` isn't installed. If the checksum doesn't match, the apply fails and the temporary file is removed, so `dest` is never a partial or unverified file. Otherwise Conn3x sets the mode and ownership, flushes the file to disk, and renames it over `dest`. On SELinux hosts the file is relabelled for its path with `restorecon`.

**Logging in.** `url` can't hold a user name or password: it's in the plan, the state, the errors and the host's process list. For a server that needs a login, put a netrc file on the host with a [`file`](/modules/file) step, using `content_wo` and mode `"0600"`, and name it in `netrc_file`. That needs `curl` on the host. Changing `netrc_file` alone doesn't plan a new download.

**Headers.** `headers` sends request headers, such as `{ Accept = "application/octet-stream" }`, and `headers_wo` sends ones kept out of plan and state, such as a private GitHub repository's `{ Authorization = "Bearer ..." }` or GitLab's `{ PRIVATE-TOKEN = ... }`. They reach `curl` on its standard input, never its command line, so they don't show in the host's process list. Only the URL's origin gets them: Conn3x follows redirects itself, and once one leads to another scheme, host or port, the rest of the way goes without them. curl on its own drops only `Authorization` and `Cookie` there. A redirect from https to plain http is refused. Headers need `curl` on the host. Changing `headers_wo` alone doesn't plan a new download, since `sha256` decides whether the file is right.

**Mode.** The default mode is `"0644"`. `owner` and `group` are set only when you give them.

**Requirements.** The host needs `curl` or `wget`. If it has neither, add a [`package`](/modules/package) step for one before this step.

## Removal

When you delete a `download` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the file where it is. `"delete"` removes it.

## From Ansible

`conn3x convert ansible` turns `get_url` tasks with a `sha256:` checksum into `download` steps, with `mode`, `owner` and `group`. A task without a SHA-256 checksum stays a TODO, since Conn3x downloads only what it can verify. `headers` carry over, except a credential such as `Authorization`, `Cookie` or a header named like a token or key: that gets a TODO to set it in `headers_wo` from a secret, and its value isn't copied. `unredirected_headers` is dropped with a note, since a download step never sends its headers to another origin.
