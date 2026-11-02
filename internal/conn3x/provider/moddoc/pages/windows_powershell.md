**Experimental.** Windows support is new, and this module may change between releases.

Use `windows_powershell` for what no Windows module covers yet. Values go in `args`, and the script reads them as `$A.name`: they arrive as data, so a quote or a `$(...)` in one is just text.

## Example usage

Create a directory once:

```hcl
step "app_dir" {
  windows_powershell {
    script  = "param($A) [void][IO.Directory]::CreateDirectory($A.dir)"
    args    = { dir = "C:\\app" }
    creates = "C:\\app"
  }
}
```

Run only while a check says the work isn't done:

```hcl
step "long_paths" {
  windows_powershell {
    script = "Set-ItemProperty -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\FileSystem' -Name LongPathsEnabled -Value 1"
    unless = "(Get-ItemProperty -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\FileSystem').LongPathsEnabled -eq 1"
  }
}
```
<!-- reference -->
## How it works

**Failing.** A script fails by throwing. Errors stop it by default, because `$ErrorActionPreference` is `Stop`. It also fails when the last native program it ran exits non-zero; for a tool with other success codes, such as `robocopy`, finish with `$global:LASTEXITCODE = 0`. Calling `exit` is reported as a failure: use `return` to finish early, and `throw` to fail.

**Guards.** Like `command`, the script runs when the step is created, when anything that defines it changes, and when a refresh finds its guards no longer hold. `unless` runs at every plan, so it must change nothing.

**Secrets.** `args_wo` stays out of the plan and state. State records only `args_hmac`, and the values are blanked from output and errors. A refresh doesn't have them, so an `unless` check that needs them sees them only during an apply.

**Timeouts.** A script is stopped after `timeout`. Conn3x stops the whole process tree when it cancels a run, but if the connection itself drops, as when the machine running Conn3x crashes, the script carries on running on the host.

**Connecting.** The `ssh` block works as it does on Linux, with its host key pinned or in `known_hosts`. Windows Server 2025 ships OpenSSH; Conn3x installs its own host key, as part of bootstrapping the host. `become` only checks that the login is elevated, since Windows has no sudo. `agent` and `become_password_file` are errors. Keep `user` as the bare name, such as `azadmin`, which still works after the host is promoted to a domain controller.

## Removal

Deleting a `windows_powershell` step does nothing on the host.
