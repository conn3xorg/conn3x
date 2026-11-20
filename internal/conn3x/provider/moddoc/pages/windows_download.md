Use `windows_download` to put a file on a Windows host from a URL, such as an installer or a zip of tools, when you know its SHA-256. Linux hosts use [`download`](/modules/download).

## Example usage

```hcl
step "tools" {
  windows_download {
    url    = "https://github.com/ip7z/7zip/releases/download/24.09/7z2409-x64.msi"
    dest   = "C:\\Installers\\7z2409-x64.msi"
    sha256 = "ec6af1ea0367d16dde6639a89a080a524cebc4d4bedfe00ed0cac4b865a918d8"
  }
}
```

From an internal mirror over plain http, removed again with the step:

```hcl
step "agent" {
  windows_download {
    url        = "http://mirror.internal/agent/agent-2.1.zip"
    dest       = "C:\\Installers\\agent-2.1.zip"
    sha256     = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
    allow_http = true
    on_remove  = "delete"
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x hashes `dest`. `in_sync` is true when it's a file with the SHA-256 `sha256`, so a file changed by hand plans a fresh download. A link at `dest`, or a folder on the way that's a link, isn't in sync, and the apply refuses it. A changed `url` with the same `sha256` is the same file, so it plans no download when `dest` already has it.

**Downloading.** Conn3x downloads on the host, the same way [`windows_package`](/modules/windows_package) does:
- **Security:** `https` only, unless `allow_http` is true, and up to five redirects, none of which may drop to `http` without it.
- **Size:** the download stops at `max_size_mb`, which defaults to 2048.
- **Writing:** the file goes into a new temp file in `dest`'s folder, held open so nothing else can change it.
- **The hash:** Conn3x checks the temp file's SHA-256. One that isn't `sha256` is deleted and the step fails, so `dest` is never a partial or wrong download, not even for a moment.
- **Replacing:** the temp file is renamed over `dest` in one step, as [`windows_file`](/modules/windows_file) writes, never following a link. A file that's already there keeps its access rules.

`dest`'s folder has to exist, so make it with a [`windows_directory`](/modules/windows_directory) step first if it may not. `timeout` defaults to `30m`.

## Removal

When you delete a `windows_download` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the file. `"delete"` removes it, or a link in its place, but not what the link points to.

## From Ansible

`conn3x convert ansible` turns `ansible.windows.win_get_url` tasks into `windows_download` steps when they give a SHA-256: `checksum` with `checksum_algorithm: sha256`. Ansible's algorithm defaults to `sha1`, so a `checksum` without `checksum_algorithm` isn't one. `url` and `dest` carry across, and `force` is dropped, since the step downloads whenever `dest`'s hash isn't `sha256`. A task without a SHA-256 stays a TODO, since `windows_download` only keeps what it can verify. So does one with a login, headers or proxy settings, which the step doesn't offer yet.
