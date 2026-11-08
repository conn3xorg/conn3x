# Adding a host module

A module is what goes inside a `step` block: `file`, `package`, `sysctl`. This guide walks through one small module, `sysctl`, from the host up, so you can build your own the same way. Most of the open module issues on the [Road to full IaCC](https://github.com/orgs/conn3xorg/projects/1) board are this shape.

Read it with the `sysctl` code open beside you. Every file named here is real, and copying its structure is the fastest way to a PR that gets merged.

## How a module fits together

A step in a circuit is lowered into an OpenTofu resource, and the built-in `conn3x` provider manages that resource over SSH. So a module is four small pieces:

| Piece | Where | What it does for `sysctl` |
| --- | --- | --- |
| Host logic | `internal/conn3x/modules/<name>/` | Validates the input, reads the host, changes the host. `internal/conn3x/modules/system/system.go` |
| Resource | `internal/conn3x/provider/` | Schema, validate, plan, read, apply. `internal/conn3x/provider/system_resources.go` |
| Registration | `internal/conn3x/provider/provider.go` and `internal/configs/conn3x_circuit.go` | Tells the provider about `conn3x_sysctl`, and tells the circuit lowering that `sysctl { }` in a step means `conn3x_sysctl`. |
| Page | `internal/conn3x/provider/moddoc/pages/<name>.md` | The introduction and examples on [docs.conn3x.org/modules/sysctl](https://docs.conn3x.org/modules/sysctl). The argument table is generated. |

Two optional pieces come later: `import` support in `internal/conn3x/provider/import.go`, and a translation in the Ansible converter, `internal/conn3x/convert/ansible/modules.go`.

## 1. The host logic

Keep everything that talks to the host in the module package, with no OpenTofu types in it. That keeps it easy to unit test.

For `sysctl` that's a struct and three functions:

```go
// Sysctl is one kernel parameter, kept in its own file in /etc/sysctl.d.
type Sysctl struct{ Key, Value string }

func (s Sysctl) Validate() error
func ReadSysctl(ctx context.Context, r modules.Runner, key string) (string, error)
func ApplySysctl(ctx context.Context, r modules.Runner, s Sysctl) error
```

A few rules every module follows:

- **Validate before anything runs.** `Validate` refuses a key that isn't a sysctl key, which also stops a key like `-p/etc/shadow` from being read as a flag. Call it at the start of apply too, not only at plan.
- **Quote everything that reaches a shell.** Commands go through `r.Run(ctx, cmd, stdin)`. Use `ssh.Quote` on every value you didn't write yourself, and put `--` before it where the command takes options.
- **Don't trust the exit code alone.** Ubuntu 24.04's `sysctl -p` exits 0 when the kernel refuses a key, so `ApplySysctl` reads the value back and fails if it didn't take. If a tool you call has a quirk like this, check the result, and write the reason in a comment.
- **Reuse what's there.** `ApplySysctl` writes its drop-in file with `file.Apply` rather than `echo >`, so mode, owner and atomic writes are already right.
- **Say what's wrong in words the reader can act on.** "the kernel kept %q after loading %s; the key may be read-only on this host, as in a container" beats "sysctl failed".

`modules.Runner` is the interface for running a command on a host. In unit tests you hand it a fake. `TestApplySysctlChecksTheKernelTookTheValue` in `system_test.go` uses a small `sysctlHost` that answers like a real host would.

## 2. The resource

The resource is the bridge between OpenTofu and the host logic. `system_resources.go` has five functions for `sysctl`.

### Schema

```go
func sysctlSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A kernel parameter, set now and kept across reboots in /etc/sysctl.d.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"name":      {Type: cty.String, Required: true, Description: "Key, such as net.ipv4.ip_forward."},
			"value":     {Type: cty.String, Required: true, Description: "Value. Separate several with spaces."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "..."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the file and the running kernel both have the value."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}
```

Every host resource has `id`, `revision`, `in_sync` and the `ssh` block. `revision` changes exactly when Conn3x changes something on the host, which is what handlers watch. The descriptions become the argument table on the docs page, so write them for a reader.

### Validate

`validateSysctl` runs at `validate` and `plan` time on the config alone. Return early while values aren't known yet (`!cfg.IsWhollyKnown()`), call the module's `Validate`, and attach errors to the argument they're about with `attrError("name", ...)`.

### Plan

```go
func planSysctl(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "sysctl", []string{"name"}, []string{"value"})
}
```

`planSynced` does the work for most modules. Its two lists are the whole decision:

- **keys** (`name`): changing one is a different object, so the plan replaces.
- **settings** (`value`): changing one is an update in place.

It also plans an update when the last read found the host out of sync, which is how drift turns into a change.

A module that grants access or runs things, such as a firewall rule or an authorized key, should remove the old object when it's renamed. Wrap the request with `deleteByDefault(req)` first, as `eos_vlan` and the firewall resources do.

### Read

Read is what refresh, plan and `conn3x drift` see. It reads the host and reports one thing: is the host what the state says?

```go
return withSync(prior, a.Content == s.Content() && s.Matches(live)), nil
```

`readPathResource` dials the host and handles errors for you. Never put what you read into state beyond `in_sync` and a few facts the reader asked for. Hosts hold secrets.

### Apply

`applyPathResource` takes two functions: one that makes the host match, and one for removal. It handles the rest: `on_remove = "forget"` (do nothing), an update that only changed how Conn3x reaches the host (do nothing), and dialing.

Your apply function returns the planned state with `withSync(planned, true)` once the host matches.

## 3. Registration

Two one-line changes.

In `internal/conn3x/provider/provider.go`, add the resource:

```go
"conn3x_sysctl": {sysctlSchema, validateSysctl, planSysctl, readSysctl, applySysctl, upgradeWith(sysctlSchema)},
```

In `internal/configs/conn3x_circuit.go`, map the step's block name to it in `circuitModules`:

```go
"sysctl": "conn3x_sysctl",
```

That's what makes `sysctl { }` valid inside a step. The lowering adds the `ssh` block and the host instances on its own.

## 4. The page

Add `internal/conn3x/provider/moddoc/pages/<name>.md` with an introduction and examples. `pages/README.md` explains the format. Two rules matter:

- Every ` ```hcl ` block must be a complete `step` block. A test wraps each one in a circuit and checks it validates.
- Lead with what the module does for the reader, then the examples, then notes after the `<!-- reference -->` line. `pages/sysctl.md` is a short one to copy.

You don't need to touch `conn3xorg/web`. Maintainers regenerate the docs site from these pages with `go run ./internal/conn3x/provider/moddoc <dir>`.

## 5. Tests

**Unit tests**, next to the code. For the module package, test `Validate` with good and bad input, and test apply against a fake `modules.Runner` for each quirk you handle. For the resource, test that validate catches bad config and that plan replaces or updates on the right attributes. `internal/conn3x/provider/eos_resources_test.go` has small examples of both.

Run them the way CI does:

```sh
go test ./internal/conn3x/... ./internal/configs/...
```

**An e2e test**, under `test/e2e/`. These build real hosts as Podman containers from `test/images/` and run the `conn3x` binary against them. `test/e2e/sysctl_test.go` and its template `test/e2e/testdata/sysctl/main.circuit.hcl.tmpl` are the pattern:

1. Start a host with `startHostWith(t, image)`, for each of `linuxImages` (Rocky Linux, Fedora, Ubuntu and Debian).
2. Write the circuit from the template, `init` and `apply`.
3. Check the host with `h.exec(...)`, not with Conn3x.
4. Plan again and expect `No changes.`

You need Podman to run them:

```sh
go test -tags e2e -run TestSysctl -v ./test/e2e/
```

CI runs the whole e2e suite on every PR. If you can't run Podman locally, open the PR and let CI run it; say so in the description.

## 6. Optional: import and the converter

**Import** lets `import` on a step adopt what a host already has. Add your resource to the `importable` table in `internal/conn3x/provider/import.go`. `sysctl`'s entry names the object by `name`, and since its read reports only `in_sync`, it adds a `hasSysctl` probe to tell a missing parameter from a different value.

**The Ansible converter** turns playbooks into circuits. If your module has an Ansible counterpart, add it to the module table in `internal/conn3x/convert/ansible/modules.go`. `sysctlModule` there translates Ansible's `sysctl` tasks. Anything it can't prove, it marks for review rather than guessing.

Either one can be its own PR after the module lands.

## Before you open the PR

- [ ] `Validate` runs at plan and at apply, and every value reaching a shell is quoted.
- [ ] Read reports `in_sync` and keeps nothing secret in state.
- [ ] Plan says `No changes.` after an apply, on every image in the e2e test.
- [ ] Errors say what's wrong and what to do.
- [ ] A page in `moddoc/pages/` with at least one example.
- [ ] Commits signed off (`git commit -s`), as [CONTRIBUTING.md](../CONTRIBUTING.md) explains.

Stuck on any of this? Ask on the issue. We'd rather help you finish than have you start over.
