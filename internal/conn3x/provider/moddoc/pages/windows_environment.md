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

**When it takes effect.** Windows hands each program its environment when the program starts. New logons, and programs they start, see the change. Programs already running, services included, keep what they had until they restart.

**Path.** `Path` is one string of folders, and setting it whole would drop whatever else is in it, so `windows_environment` refuses it. Give each folder its own [`windows_path`](/modules/windows_path) step.

**Changes.** Changing `value` or `state` updates the variable in place. Changing `name` or `level` replaces the step.

## Removal

`on_remove = "forget"`, the default, leaves the variable. `on_remove = "delete"` removes it.
