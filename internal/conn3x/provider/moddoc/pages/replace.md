Use `replace` to change every match of a regular expression in a file that already exists. To make sure one line is there, use [`line`](/modules/line). To set an option in an INI-style file, use [`ini`](/modules/ini).

## Example usage

Change a hostname everywhere it appears:

```hcl
step "new_mirror" {
  replace {
    path    = "/etc/app/mirrors.conf"
    regexp  = "old\\.example\\.com"
    replace = "new.example.com"
  }
}
```

Keep part of what matched. `$${1}` is `${1}` in a quoted string, and `$1` works when no letter or digit follows it:

```hcl
step "new_port" {
  replace {
    path    = "/etc/app/listen.conf"
    regexp  = "^listen ([a-z.]+):80$"
    replace = "listen $${1}:8080"
  }
}
```

Delete every match, here whole comment lines:

```hcl
step "no_comments" {
  replace {
    path    = "/etc/app/generated.conf"
    regexp  = "^#.*\\n"
    replace = ""
  }
}
```
<!-- reference -->
## How it works

**Reading.** Every plan reads the file on the host and applies the replacement to a copy of its content. If the result is the same as the file, the step is in sync and nothing is planned. Otherwise the plan shows an update, and `conn3x drift` reports it.

**Matching.** `regexp` uses [Go's syntax](https://pkg.go.dev/regexp/syntax), which has no lookaheads, lookbehinds or backreferences. It runs over the whole file, so a match can cross lines with `\n`. `^` and `$` match at each line, and `.` doesn't match a line break, but a negated class like `[^#]` does.

**The replacement.** `$1`, `${1}` and `${name}` bring in what a group matched, and `$$` is a dollar sign. In a quoted string, write `${1}` as `$${1}`. `$1x` means a group called `1x`, so write `$${1}x`. A reference to a group that isn't in `regexp` is an error, rather than expanding to nothing and losing text.

**Plans that have to settle.** After an apply, `regexp` must find nothing more to change, or every plan would change the file again. `regexp = "foo"` with `replace = "foobar"` can't settle, and `conn3x validate` says so. With a group, as in `(foo)` and `$1$1`, Conn3x can't tell until it sees the file: the plan or apply that finds a match fails with the reason, and the file isn't written. Tighten the pattern so it matches only the old text, for example `foo$`.

**Writing.** Conn3x writes the edited content the same way as [`file`](/modules/file): to a temporary file in the same directory, renamed over the old one, and relabelled with `restorecon` on SELinux hosts. If `path` is a symlink, the file it points to is written and the link stays. The file keeps its mode, owner and group. When nothing changes, the file isn't written. Steps that edit the same file take turns.

**Missing files.** A missing file is an error. `create` isn't allowed, as a new file has nothing to replace.

**Secrets.** `regexp` and `replace` are stored in state and shown in plans, like the text of a [`line`](/modules/line) step. The file's content isn't stored.

**Conflicts.** If another step in the same circuit writes the whole file with `file` or `template`, `conn3x validate` warns you, because each apply would undo the other.

## Removal

When you delete a `replace` step, the file stays as it is. `on_remove = "delete"` isn't allowed, because the old text is gone.

## From Ansible

`conn3x convert ansible` turns `ansible.builtin.replace` tasks into `replace` steps when it can prove the pattern means the same in Go as in Python, and rewrites backreferences: `\1` and `\g<1>` become `${1}`, `\g<name>` becomes `${name}`, and a `$` becomes `$$`. A reference to a group that doesn't exist stays a TODO, as Ansible would fail on it.

These stay a TODO with the reason:

- Lookaheads, lookbehinds, backreferences inside the pattern, inline flags such as `(?i)`, and any other `(?` form except `(?:` and `(?P<name>`.
- `\d`, `\w`, `\s` and `\b`, which cover Unicode in Python and only ASCII in Go, and any other lettered escape except `\t`, `\n`, `\r`, `\f`, `\v`, `\a` and `\A`. Rewriting `\d` as `[0-9]` makes the task convertible, if that's what you meant.
- `[[:alpha:]]`, which is a class in Go and plain characters in Python, and `a{,3}`, which is a repeat in Python and plain text in Go.
- A pattern that can match nothing, like `x*` or `^.*$`, because Python and Go replace different empty matches.
- A replacement the pattern would match again, which never settles.
- `after`, `before`, `backup`, `validate`, `mode`, `owner`, `group`, an `encoding` other than UTF-8, tasks written as `key=value` text, loops, and unquoted values that YAML could read as something else, such as `yes` or `1.5`.

Ansible leaves a growing replacement to you: it would append again on every play. A step with a group that grows, like `(foo)` and `\1\1`, converts, then fails at plan or apply with the reason instead.
