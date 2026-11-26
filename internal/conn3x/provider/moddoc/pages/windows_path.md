**Experimental.** New, and tested on GitHub's Windows Server 2022 and 2025 runners, not yet on an Azure server. See [Windows readiness](https://github.com/conn3xorg/conn3x/blob/main/docs/windows-readiness.md).

Use `windows_path` to put one folder on a Windows host's `Path`, such as a tool's `bin` folder, and leave every other folder where it is. `Path` is one long string, so setting it whole with `setx` or `SetEnvironmentVariable` is how servers lose half their tools, and how `%SystemRoot%` gets expanded into a fixed `C:\Windows`. This step changes one folder and nothing else.

## Example usage

```hcl
step "go_on_path" {
  windows_path {
    element = "C:\\Program Files\\Go\\bin"
  }
}
```

Take an old folder out of the user's own `Path`:

```hcl
step "old_tool_gone" {
  windows_path {
    element = "C:\\OldTool"
    scope   = "user"
    state   = "absent"
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x reads `Path` from the registry, the machine's or the user's, without expanding it, and looks for the folder. Folders compare the way Windows compares them: `C:\Tools`, `c:\tools` and `C:\Tools\` are the same folder.

**Applying.** To add the folder, Conn3x reads `Path` again and writes it back with the folder at the end. To remove it, every copy of it comes out. The other folders, their order and their `%SystemRoot%`-style names are written back exactly as they were, and `Path` keeps its type, so it still expands.

**When it takes effect.** After a change, Conn3x broadcasts `WM_SETTINGCHANGE` with `Environment`, so Explorer reloads `Path` and a program you start from Explorer finds the folder without logging off. A hung window or a slow broadcast doesn't fail the step. New logons, and programs they start, see the change too. Programs already running, services included, keep the `Path` they started with until they restart.

**Changes.** Changing `state` updates `Path` in place. Changing `element` or `scope` replaces the step.

## Removal

`on_remove = "forget"`, the default, leaves the folder on `Path`. `on_remove = "delete"` takes it out.
