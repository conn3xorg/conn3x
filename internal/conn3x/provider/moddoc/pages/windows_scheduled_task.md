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

**Who it runs as.** `SYSTEM`, `LOCAL SERVICE` and `NETWORK SERVICE` need no password. Another account runs with `password_wo` when the task needs the network, or without one as S4U, which runs unattended but can't reach other machines. Accounts are compared by SID, so `svc` and `LAB\svc` don't drift. Windows refuses an S4U task for any account but the login Conn3x uses, as its SSH session holds no password to vouch for one: give that account `password_wo`.

**Passwords.** `password_wo` goes to the host on stdin, never on a command line, and reaches Task Scheduler through a COM method rather than a cmdlet, so a policy that records cmdlet parameters never sees it. State keeps a keyed hash. Windows stores the password where nobody can read it back, so a password changed on the host doesn't show as drift; Conn3x registers the task again whenever the value you give changes.

**What it runs.** Whoever can change the program a task runs can act as the task's user, at any run level: the built-in Administrator and the service accounts have full rights without `highest`. So for every task, Conn3x checks on the host that the program exists, that only administrators can change it, its folder or any folder on the way, and that nobody else can add files next to it, where a planted DLL would load. A tool in someone's own profile, such as `C:\Users\alice\tool.exe`, is refused for that reason. Install the program before the step that schedules it.

**Paths in arguments.** Every full path in `arguments` gets the same check, quoted or not, with `/` or `\`. A path that doesn't exist yet is judged by the deepest folder on its way that does, since whoever can add files there can put something at that path later. Conn3x refuses a share, a relative path such as `..\job.bat` or `scripts/job.bat`, and any `%`, `^` or `!`, which cmd.exe or Task Scheduler expand after the check. The working folder is checked like the program's folder. `execute` and `working_directory` can't use `%NAME%` either.

**Interpreters.** A program that runs code from its arguments, such as `cmd.exe`, `powershell.exe`, `wscript.exe`, `rundll32.exe` or `python.exe`, needs `allow_interpreter = true`. Conn3x checks the paths it can see in the arguments, but not code inside them: `-Command` text, `-EncodedCommand`, or a script name a shell finds on its own. Setting it says you've made sure everything that code runs is admin-only.

**Arguments.** `arguments` are stored in the task, readable by administrators, and in state. Never pass a secret there.

## Removal

By default, deleting a `windows_scheduled_task` step deletes the task. With `on_remove = "forget"` the task stays.
