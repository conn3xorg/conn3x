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

**Arguments.** Each part of `arguments` must be a switch (`-v`, `--port=8080`, `/quiet`), a plain word with no `\`, `/` or `:`, an http or https URL, or a full path on a drive, such as `--config C:\ProgramData\App\cfg.json`. Anything else is refused: a relative path, a share, a `file:` URL, a drive-relative path such as `D:x.dll`, a short name such as `PROGRA~1`, a folder name ending in a space or a dot, and any `%`, `^` or `!`, which are expanded after the check. A quoted path with spaces counts as one path. Every path gets the program's check; one that doesn't exist yet is judged by the deepest folder on its way that does, since whoever can add files there can put something at that path later. Paths must be on a fixed NTFS drive, where access rules exist to check. `execute` and `working_directory` follow the same rules. A switch value such as `/log:C:\x` or `--log=C:\x` is checked as a path too.

**Data paths.** A log the task writes or a file it only reads as data can sit somewhere ordinary users can write, such as `C:\Logs\job.log`. List it in `data_paths` and it skips the admin-only check. It must appear exactly once in `arguments`, matching apart from case, and still be a plain full path in ASCII on a fixed NTFS drive. Anyone who can write there can change that file, so never list a file or folder the program loads code or settings from, or runs. Prefer a file to a folder: a program given a folder may load anything someone puts in it. A path that isn't listed gets the full check.

**Interpreters.** A program that runs code from its arguments, such as `cmd.exe`, `powershell.exe`, `wscript.exe`, `rundll32.exe` or `python.exe`, needs `allow_interpreter = true`. Conn3x checks the paths it can see in the arguments, but not code inside them: `-Command` text, `-EncodedCommand`, or a script name a shell finds on its own. Setting it says you've made sure everything that code runs is admin-only. A bare name it runs, such as `job` in `/c job`, is found through `PATH` and the working folder, so those folders matter too. A renamed copy of an interpreter is caught by the name Windows records inside it.

**Arguments.** `arguments` are stored in the task, readable by administrators, and in state. Never pass a secret there.

## Removal

By default, deleting a `windows_scheduled_task` step deletes the task. With `on_remove = "forget"` the task stays.
