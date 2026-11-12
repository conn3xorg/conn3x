# Design note: steps that run when an earlier step fails

Status: for [#522](https://github.com/conn3xorg/conn3x/issues/522). `rescue`, `always` and the converter are built; `prereq` isn't yet.
Status: for [#522](https://github.com/conn3xorg/conn3x/issues/522). `rescue`, `always` and `prereq` are built; the converter is in its own change.

## Where the build differs

- A rescue can't `notify` a handler yet. Put the restart in the rescue.
- Applying a saved plan warns that no rescue will run, rather than refusing, the way a saved plan already applies a batched circuit whole.
- A rescued host still counts against `max_failures` (open question 2 below, answered "not yet").
- Rescues run only in root module circuits, as batches do.
- An always block runs where a watched step or handler changed something or failed. A step with nothing to change isn't in the apply, so nothing runs after it.
- An always block that fails fails the apply, even when every step succeeded.
- The converter leaves a block that sets `when` or another keyword for review, and a block with rescue or always inside another's, rather than flattening those. A rescue task that notifies a handler goes to review too.
- A prereq runs only before a step's own apply: a batch's prereqs run with that batch. The plan after the prereqs is checked against the one you approved, as a batch's is.
- One rescue phase, and one always phase, covers every circuit: each rescue gets its own hosts, through `CONN3X_RESCUE_HOSTS`, and the plan targets rescues only.

## What people want

A config change goes out, the restart after it fails, and the host is left
with a service that won't start. In Ansible you'd have written:

```yaml
- block:
    - copy: { src: app.conf, dest: /etc/app/app.conf, backup: true }
    - service: { name: app, state: restarted }
  rescue:
    - command: cp /etc/app/app.conf.bak /etc/app/app.conf
    - service: { name: app, state: restarted }
  always:
    - command: /usr/local/bin/lb-enable {{ inventory_hostname }}
```

Three things are in there, and Salt adds a fourth:

- **rescue**: steps that run on a host only when a step in the block failed there.
- **always**: steps that run on every host where the block ran, failed or not.
- **onfail** (Salt): the same as rescue, watching named states instead of a block.
- **prereq** (Salt): a step that runs before another only when that one is about to change. Take the host out of the load balancer, but only if its config is changing.

Today `conn3x convert ansible` leaves every `rescue` and `always` as a TODO, and there's nothing to write by hand instead.

## Why it doesn't fit the graph

Every step is a resource, and the order between steps is a dependency edge. Two things stand in the way.

1. **A failure stops everything downstream.** When a resource fails to apply, the graph walker skips every node that depends on it (`internal/dag/walk.go`, "upstream of %q errored, so skipping"). A rescue step has to depend on the steps it watches, or it could run before them, and that dependency is exactly what makes the walker skip it.
2. **The plan fixes every action before apply starts.** A plan says "create this, update that". Whether a rescue step runs depends on something only the apply finds out. The plan has no way to say "create this, if that fails".

Salt's prereq has the second problem the other way round. Whether it runs is known at plan time, from the other step's change, but a step's arguments can't read another step's planned action.

## Options

### 1. A new kind of edge in the walker

An edge that means "after this, even if it failed", and a planned action that means "only if it failed". This is the most direct fit, and it touches the core twice: `internal/dag` and the plan format. Both are upstream code. The hook budget is at 9 of 9, and a change to how the walker treats failure would be the riskiest hook we carry, since every resource goes through it. A plan with conditional actions would also be a plan no OpenTofu tool reads correctly.

### 2. One resource for the whole block

A `conn3x_block` resource whose provider runs the inner steps in order, then rescue or always as needed. It needs no core changes, but the block becomes a second engine inside the first. The inner steps lose their own plan diffs, `import`, `for_each`, handlers and `when`, or the provider has to rebuild each of them. A plan would show one opaque change where it shows five today.

### 3. Phases in `conn3x apply` (recommended)

A batched apply already runs as several plans and applies: `cmd/conn3x/conn3x_batch.go` re-runs conn3x for each batch, narrows each plan with `-limit` and a circuit (`CONN3X_BATCH_CIRCUIT`), checks each plan against the one you approved, and reads each apply's JSON stream for the report. Rescue, always and prereq can run the same way, as extra phases around the normal apply. Nothing changes in the graph or the plan format, and every rescue step is an ordinary step, with its own diff, `when`, `for_each` and handlers.

## The proposal

### Syntax

Rescue and always steps watch named steps, the way Salt's onfail does. There's no `block` to nest, because circuits don't nest steps anywhere else:

```hcl
circuit "app" {
  hosts    = var.hosts
  strategy = "per_host"

  step "backup" {
    command {
      command = "cp /etc/app/app.conf /var/backups/app.conf"
    }
  }

  step "config" {
    file {
      path    = "/etc/app/app.conf"
      content = file("app.conf")
    }
    notify = [handler.restart]
  }

  handler "restart" {
    service {
      name   = "app"
      action = "restart"
    }
  }

  rescue "restore" {
    watches = [step.config, handler.restart]
    command {
      command = "cp /var/backups/app.conf /etc/app/app.conf && systemctl restart app"
    }
  }

  always "lb_enable" {
    watches = [step.config, handler.restart]
    on      = "lb"
    command {
      command = "lb-enable ${each.key}"
    }
  }

  prereq "lb_disable" {
    before = [step.config]
    on     = "lb"
    command {
      command = "lb-disable ${each.key}"
    }
  }
}
```

`rescue`, `always` and `prereq` take everything a `step` takes except `depends_on`, `run_once` and `import`. Several of each run in the order they're written. `watches` can name handlers, since a failed restart is the commonest reason to roll back. The `backup` step is a placeholder: a real circuit would guard it, or a `file` option could keep the old content.

### What apply does

1. **Plan.** As now. Rescue, always and prereq steps lower with a `when` that's false outside their own phase, so they're never in this plan. Under the plan, apply lists them: "If `config` or the `restart` handler fails on a host, `restore` runs there."
2. **Prereq.** For each host where a step in `before` has a change, plan the prereq steps with `-limit` set to those hosts, check that the plan holds only prereq steps, and apply it. Then plan again and check it against the plan you approved, as each batch does.
3. **Apply.** As now, or batch by batch with `batch_size`.
4. **Rescue.** Read the apply's JSON stream for the hosts where a watched step failed. For those hosts, plan the rescue steps only, check the plan, and apply it.
5. **Always.** The same, for every host where a watched step was in the apply, whether or not it failed.

You approve once, at step 1, as with batches. `-auto-approve` covers every phase.

### State

A phase's steps go into state when they apply. On the next plan their `when` is false again, and the plan would show them being removed. So after each phase, apply drops those instances from state, as `conn3x state rm` would, and the next plan doesn't mention them. They're actions, not things a host has, much like a handler.

### Exit code and report

**A rescued failure is still a failure: apply exits 1.** Ansible counts a rescued host as fine, but CI that sees exit 0 after a failed restart will deploy the next change on top of it. The report marks the step failed and the host rescued, so a dashboard can tell the two apart. If people want Ansible's behaviour, a circuit setting can come later.

### What it refuses

The same things a batched apply refuses, for the same reasons: `-target`, `-exclude`, `-json`, `-json-into`, and the remote and cloud backends. A destroy runs no rescues.

## What it costs

- No new upstream hooks. The work is in `internal/configs` (the three new blocks and their lowering) and `cmd/conn3x` (the phases). The batch runner's re-exec, plan checks and stream reading are shared, not copied.
- A rescue adds two plans and an apply, but only on a run where something failed. A prereq adds a plan and an apply on every run where its target changes.
- `watches` and `before` name steps in the same circuit only. Watching another circuit's steps can come later.

## The converter

- `block` with `rescue` and `always` becomes the block's tasks as steps, then a `rescue` and an `always` that watch all of them.
- A nested block flattens: its tasks join the outer list.
- A rescue that reads `ansible_failed_task` or `ansible_failed_result` goes to review. Conn3x has nothing like them yet.

## Open questions

1. Is `watches` a clear name, or would `after_failure_of` read better in a circuit?
2. Should a rescue that succeeds let the next batch start, where a plain failure counts against `max_failures`? Leaning yes: the host is back in a known state.
3. Drop phase instances from state quietly, or keep them and hide them from the next plan? Dropping is simpler, and loses the record that they ran. The report keeps it.

## Order of work

1. `rescue`, with `watches`, phases 3 and 4, the state cleanup and the report. This is the one people ask for.
2. `always`.
3. The converter's block, rescue and always.
4. `prereq`, which is the most different and the least asked for.
