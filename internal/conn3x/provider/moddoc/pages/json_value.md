Use `json_value` to own one value in a JSON config file and leave the rest of it alone: an app's port, a log level, a feature flag. Many Node.js and Java apps keep their settings this way. Every byte the step doesn't own stays as it was, indentation and key order included, so a diff of the file shows only your change.

## Example usage

Set the port:

```hcl
step "port" {
  json_value {
    path  = "/etc/myapp/config.json"
    key   = "server.port"
    value = jsonencode(9090)
  }
}
```

Add a setting, making the objects on the way:

```hcl
step "log_level" {
  json_value {
    path  = "/etc/myapp/config.json"
    key   = "logging.level"
    value = jsonencode("warn")
  }
}
```

Change one element of a list:

```hcl
step "first_upstream" {
  json_value {
    path  = "/etc/myapp/config.json"
    key   = "upstreams[0].host"
    value = jsonencode("10.0.0.5")
  }
}
```

Take a key out:

```hcl
step "no_debug" {
  json_value {
    path  = "/etc/myapp/config.json"
    key   = "debug"
    state = "absent"
  }
}
```
<!-- reference -->
## How it works

**The key.** Object keys joined by dots, with `[n]` after one for an array element, counted from 0. A key with a dot or a bracket in its name can't be named.

**The value.** It's JSON text, so `jsonencode` keeps its type: `jsonencode(9090)` is a number, `jsonencode("9090")` a string, and `jsonencode({ enabled = true })` an object. Conn3x compares values, not text, so `8080` and `8080.0` are equal, and an object's keys can be in any order. An equal value is left as it's written. A different one is replaced where it is, written compactly.

**Adding.** A missing key goes after the object's last member, on its own line and indented as that member is when the object spans lines, or on the same line when it doesn't. Objects missing on the way are made. Arrays aren't: an index past the end of an array is an error, and so is an index into something that isn't there. An empty file starts as `{}`, and so does a missing one with `create = true`; without it, a missing file is an error.

**Taking out.** `state = "absent"` removes the key with its comma and line, and does nothing when the key isn't there. The object it was in stays, even when that leaves it empty. Array elements can't be taken out.

**The file.** It's read and written as [`line`](line.md) reads and writes, with the file's owner and mode kept, and it must be valid JSON before Conn3x touches it. Comments, as in JSONC, make it invalid. Every plan reads the file again, so a value changed by hand shows the step out of sync, and the next apply puts it back.

## Removal

Deleting a `json_value` step leaves the value. With `on_remove = "delete"`, it takes the key out.
