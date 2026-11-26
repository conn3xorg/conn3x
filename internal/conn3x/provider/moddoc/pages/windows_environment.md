**Experimental.** New, and tested on GitHub's Windows Server 2022 and 2025 runners, not yet on an Azure server. See [Windows readiness](https://github.com/conn3xorg/conn3x/blob/main/docs/windows-readiness.md).

Use `windows_environment` to set an environment variable for the whole machine, such as `JAVA_HOME` or a proxy, or for the account Conn3x logs in as. It's the `[Environment]::SetEnvironmentVariable` you'd otherwise run by hand on every server, kept in a plan so drift shows.

## Example usage

```hcl
step "java_home" {
  windows_environment {
    name  = "JAVA_HOME"
    value = "C:\\Program Files\\Eclipse Adoptium\\jdk-21"
  }
}
```

A value with `%` in it is stored to expand, as Windows' own variables are:

```hcl
step "app_logs" {
  windows_environment {
    name  = "APP_LOGS"
    value = "%ProgramData%\\App\\logs"
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x reads the variable from the registry, under `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment` for the machine or `HKCU\Environment` for the user, without expanding it. `in_sync` is true when the value is exactly `value`, so `%ProgramData%` compares as `%ProgramData%`, not as the folder it names.

**Applying.** Conn3x writes the value to the registry. A variable that's already there keeps its type; a new one with `%` in it is stored to expand, and one without is plain text.

**When it takes effect.** Windows hands each program its environment when the program starts. After a change, Conn3x broadcasts `WM_SETTINGCHANGE` with `Environment`, as Ansible does, so Explorer reloads it and a program you start from Explorer sees the new value without logging off. A hung window or a slow broadcast doesn't fail the step: the value is already written. New logons, and programs they start, see the change too. Programs already running, services included, keep what they had until they restart.

**Path.** `Path` is one string of folders, and setting it whole would drop whatever else is in it, so `windows_environment` refuses it. Give each folder its own [`windows_path`](/modules/windows_path) step.

**Changes.** Changing `value` or `state` updates the variable in place. Changing `name` or `level` replaces the step.

## Removal

`on_remove = "forget"`, the default, leaves the variable. `on_remove = "delete"` removes it.

## From Ansible

`conn3x convert ansible` turns `ansible.windows.win_environment` tasks into `windows_environment` steps, with `name`, `value`, `level` and `state` carried over. A task with `variables` becomes one step per variable, and an empty value removes its variable, as it does in Ansible. So does a task with no `state` and no `value`.

`level: user` converts, with a review note. The step sets the variable for the account the `ssh` block logs in as, where Ansible sets it for the user the task runs as, which is the become user under `become`. With `level: user`, a play or task that sets `become_user` stays a TODO. `level: process` stays a TODO too: it lasts only as long as the Ansible module's own process, so there's nothing for a step to keep. A task that sets `Path` whole stays a TODO; give each folder a `windows_path` step instead.

One difference is in the registry type. Ansible writes with .NET's `[Environment]::SetEnvironmentVariable`, which always stores plain text (`REG_SZ`), even for a value with `%` in it and even over a variable that was stored to expand. So under Ansible, `%ProgramData%\App\logs` reaches programs as those literal characters. Conn3x keeps an existing variable's type and stores a new one with `%` to expand (`REG_EXPAND_SZ`), so the same value reaches programs as `C:\ProgramData\App\logs`. If a program needs the `%` kept as written, create the variable as plain text first; Conn3x keeps that type from then on.
