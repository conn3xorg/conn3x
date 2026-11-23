Use `compose_project` to keep a Compose project up: the `compose.yaml` a self-hosted app ships with, run with `docker compose` on Docker or `podman-compose` on Podman. It's `community.docker.docker_compose_v2`. A service someone stopped by hand, or a Compose file someone edited, shows in the next plan, and the apply brings it back.

## Example usage

A project whose Compose file lives in the circuit, so a change to it plans an `up` in the same run:

```hcl
step "app" {
  compose_project {
    project_dir = "/opt/app"
    content     = <<-EOT
      services:
        web:
          image: docker.io/library/nginx:1.27
          ports: ["8080:80"]
        cache:
          image: docker.io/library/redis:7.4
    EOT
    remove_orphans = true
    wait           = true
  }
}
```

A project whose files are on the host already, with one profile on and two services kept stopped:

```hcl
step "tools" {
  compose_project {
    project_dir  = "/srv/tools"
    project_name = "tools"
    files        = ["compose.yaml", "compose.prod.yaml"]
    profiles     = ["admin"]
    services     = ["adminer", "mailpit"]
    state        = "stopped"
  }
}
```

On Podman, install `podman-compose` first. On Rocky Linux and RHEL it's in EPEL:

```hcl
step "epel" {
  package {
    name = "epel-release"
  }
}
```

```hcl
step "podman-compose" {
  package {
    name = "podman-compose"
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x runs `compose config --services` and `compose ps --format json` in `project_dir`, and takes a SHA-256 over the Compose and env files. `in_sync` is false when a wanted service isn't running (or, with `state = "stopped"`, is), when the files' hash differs from the one recorded at the last apply in `config_hash`, when the files don't parse, or, with `remove_orphans`, when containers of a service no longer in the files are left. With `files` unset, the hash covers every name Compose looks for, `compose.yaml` to `docker-compose.override.yml`. With `env_files` unset, it covers `.env`. A one-shot service, such as a `migrate` that `web` waits for with `condition: service_completed_successfully`, counts as done once its container exited 0, so it doesn't show as drift. One that exited with another code, or has no container, plans an `up`.

**The Compose file.** Set `content` and Conn3x writes it before each change to the one file in `files`, or `compose.yaml`, with mode 0600, even when the file was there with another mode. That's the way to go when the file belongs to the circuit: a change to `content` plans an `up` straight away. Leave `content` unset and the files must be on the host already, written by a `file` step, a `git` step or by hand. A change to them shows on the plan after they're written, since a plan reads the host before anything in it runs.

**Applying.** `present` runs `up -d`, which starts what stopped and recreates what changed. Docker recreates only the services whose settings changed; podman-compose recreates the whole project when any of it did. `stopped` runs `up -d --no-start` and then `stop`, so the containers exist and don't run. `absent` runs `down`. `services` limits each of them to those services. After the change, Conn3x reads the project again, and the apply fails if a service still isn't as wanted: look at `compose logs` for why.

**Pulling.** `pull = "policy"`, the default, passes nothing, so Compose follows each service's `pull_policy` and pulls only what's missing. `always` pulls on every apply that runs `up`; a plan that finds nothing to do doesn't pull. `missing` and `never` are Docker's `--pull` values. podman-compose pulls missing images by default and can't be told never to, so `never` fails there.

**Orphans.** A service you remove from the file keeps running, as Compose leaves it, unless `remove_orphans = true`. Then `up` and `down` pass `--remove-orphans`, and a plan shows orphans as drift.

**Docker or Podman.** `docker compose` is the Compose v2 plugin. On Podman, Conn3x runs `podman-compose` by name, not `podman compose`, which hands over to `docker-compose` when that's installed. podman-compose has no `--wait` and reads only one env file, so `wait = true` or two `env_files` fail there with a message saying so.

**Not yet.** Building images, `recreate`, `scale`, `timeout` and removing images on `down` aren't settings of this step. Build images in CI and pull them.

## Removal

`on_remove = "forget"`, the default, leaves the project running. `on_remove = "delete"` runs `compose down`, with `--remove-orphans` when that's set. Neither removes volumes, images or the Compose file: `down` never gets `--volumes` from Conn3x, so the data stays. `state = "absent"` takes the project down while the step stays in the circuit.

## From Ansible

`conn3x convert ansible` turns `community.docker.docker_compose_v2` tasks into `compose_project` steps with `engine = "docker"`. `project_src`, `project_name`, `files`, `env_files`, `profiles`, `services`, `remove_orphans`, `pull`, `wait` and `state` `present`, `stopped` and `absent` carry over. `recreate: auto`, `build: policy` and `dependencies: true`, the defaults, are dropped, since the step does the same.

What stays a TODO: `state: restarted`, which is an action rather than a state, so it belongs in a handler; `definition`, which Ansible writes to a temporary directory and deletes, where this step needs a directory on the host (move it into `content` with a `project_dir`); `remove_volumes` and `remove_images`, which this step never does; and `build`, `recreate`, `dependencies: false`, `scale`, `timeout` and `wait_timeout`.
