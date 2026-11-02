**Experimental.** Windows support is new, and this module may change between releases.

Use `windows_scheduled_task` to run one program on a schedule, at boot or at logon. Conn3x compares the settings you give, not the task's XML, which Windows rewrites in its own way.

## Example usage

```hcl
step "nightly_cleanup" {
  windows_scheduled_task {
    name      = "Nightly cleanup"
    path      = "\\Conn3x\\"
    execute   = "C:\\Windows\\System32\\cleanmgr.exe"
    arguments = "/sagerun:1"
    user      = "SYSTEM"

    trigger {
      type = "daily"
      at   = "2026-01-01T03:00:00"
    }
  }
}
```

```hcl
step "report_upload" {
  windows_scheduled_task {
    name        = "Report upload"
    execute     = "C:\\Program Files\\Reports\\upload.exe"
    user        = "LAB\\svc-reports"
    password_wo = "use an ephemeral variable here"

    trigger {
      type = "boot"
    }
  }
}
```
<!-- reference -->
## How it works

**Who it runs as.** `SYSTEM`, `LOCAL SERVICE` and `NETWORK SERVICE` need no password. Another account runs with `password_wo` when the task needs the network, or without one as S4U, which runs unattended but can't reach other machines. Accounts are compared by SID, so `svc` and `LAB\svc` don't drift.

**Passwords.** `password_wo` goes to the host on stdin, never on a command line, and reaches Task Scheduler through a COM method rather than a cmdlet, so a policy that records cmdlet parameters never sees it. State keeps a keyed hash. Windows stores the password where nobody can read it back, so a password changed on the host doesn't show as drift; Conn3x registers the task again whenever the value you give changes.

**Programs that run with high rights.** For a task as `SYSTEM`, `LOCAL SERVICE` or `NETWORK SERVICE`, or with `run_level = "highest"`, Conn3x checks on the host that only administrators can change the program, its folder, or any folder on the way, and that nobody else can add files next to it, where a planted DLL would load. It refuses otherwise. It can't see into `arguments`, so a script a program runs, such as `powershell.exe -File C:\scripts\job.ps1`, isn't checked: keep it in a folder only administrators can change.

**Arguments.** `arguments` are stored in the task, readable by administrators, and in state. Never pass a secret there.

## Removal

By default, deleting a `windows_scheduled_task` step deletes the task. With `on_remove = "forget"` the task stays.
