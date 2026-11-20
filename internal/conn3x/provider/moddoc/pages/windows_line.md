Use `windows_line` to make sure one line is, or isn't, in a text file on a Windows host, such as a setting in an `.ini` file, while leaving the rest of the file alone. It's the [`line`](/modules/line) step for Windows, with the same arguments and the same matching. Use [`windows_file`](/modules/windows_file) to own a whole file.

## Example usage

```hcl
step "port" {
  windows_line {
    path   = "C:\\App\\app.ini"
    regexp = "^port="
    line   = "port=8080"
  }
}
```

A line added under a section, in a file made if it's missing:

```hcl
step "debug_off" {
  windows_line {
    path         = "C:\\App\\app.ini"
    line         = "debug=0"
    insert_after = "^\\[server\\]"
    create       = true
  }
}
```
<!-- reference -->
## How it works

**Matching.** As in [`line`](/modules/line):
- **Replacing:** with `regexp`, the last line that matches is replaced with `line`. When none matches, and `line` isn't there already, it's added after the last match of `insert_after`, before the first match of `insert_before`, or at the end.
- **Removing:** with `state = "absent"`, every match goes.
- **`backrefs`:** makes `line` a template for the matched line.

The patterns are Go regular expressions.

**Encoding and line endings.** Conn3x reads the file's bytes and decodes them as UTF-8, with or without a byte order mark, or UTF-16 LE with one, as Notepad's "Unicode" writes. It edits the text, and writes it back the same way. A file with `\r\n` line endings keeps them, including the new line, and a file with `\n` keeps those. A file with no line ending yet, empty or a single line, gets `\r\n`, as one it creates does. So an edit changes only the lines it's about.

A file in another encoding (UTF-16 big-endian, a legacy code page) is refused rather than guessed at. So is one that couldn't be written back byte for byte, such as one mixing `\r\n` and `\n` endings. A file Conn3x creates, with `create = true`, is UTF-8 without a byte order mark, with `\r\n` endings.

**Reading.** On every plan, Conn3x reads the file and applies the edit in memory, and `in_sync` is true when that changes nothing. A missing file is in sync for `state = "absent"`. It reads the file's content, where the other Windows steps read only a hash, up to 2 MiB. A link at the path or on the way, or a folder, is refused.

**Writing.** A change is written the way [`windows_file`](/modules/windows_file) writes content without `acl`: to a temp file beside it, renamed over it in one step, never following a link, and keeping the file's access rules.

## Removal

When you delete a `windows_line` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the file as it is. `"delete"` takes the line back out, the same as `line`'s.

## From Ansible

`conn3x convert ansible` turns `community.windows.win_lineinfile` tasks into `windows_line` steps, the way it turns `lineinfile` into `line`.
- **Arguments:** `path` (or `dest`), `line`, `regex`, `state`, `insertafter`, `insertbefore`, `create` and `backrefs` carry across.
- **`newline`:** Ansible's `newline: windows`, the default, rewrote every line ending in the file to `\r\n`, so the converted step carries a note that `windows_line` keeps the file's own endings.
- **Left as TODOs:** `newline: unix`, an `encoding` other than `auto`, `backup` and `validate`.
