Use `container` to keep a container running with Docker or Podman: its image, ports, volumes, environment and restart policy. Each step is one container, by name. The host needs Docker or Podman installed: a `package` step before this one.

## Example usage

Run nginx with a published port and a read-only site directory:

```hcl
step "web" {
  container {
    name    = "web"
    image   = "docker.io/library/nginx:1.27"
    ports   = ["8080:80"]
    volumes = ["/srv/site:/usr/share/nginx/html:ro"]
    restart = "unless-stopped"
  }
}
```

Run a worker with its own command and environment, on Podman, removed with the step:

```hcl
step "worker" {
  container {
    name      = "worker"
    image     = "ghcr.io/example/worker:2.4.1"
    command   = ["worker", "--queue", "default"]
    env       = { QUEUE_URL = "amqp://queue.internal:5672", LOG_LEVEL = "info" }
    engine    = "podman"
    restart   = "always"
    on_remove = "delete"
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x runs `docker container inspect`, or Podman's, and compares the container with the step: its image, published ports, mounts, restart policy, the `command` if you set one, and the `env` you set. `inspect` also lists variables the image sets itself, so only the keys in `env` are compared. `in_sync` is true when all of those match and the container is running.

**Images.** Write the image in full, such as `docker.io/library/nginx:1.27`. Docker keeps a short name as written, Podman stores the full reference, and Conn3x compares the two as the same when the short name means Docker Hub. A short name that Podman resolves to another registry shows as a difference on every plan. A tag that now points at a newer image doesn't change anything: the image as written is what's compared. To roll forward, change the tag.

**Applying.** A container's settings can't change while it exists, so any difference means Conn3x removes the container and runs it again under the same name. Named volumes and host directories keep their data. If the image isn't on the host yet, Conn3x pulls it first. A container that's only stopped is started, not recreated.

**Secrets.** `env` is sensitive. Conn3x passes it to the engine on standard input with `--env-file /dev/stdin`, so the values don't appear in the host's process list. They're still in the container's configuration, where `inspect` shows them to anyone who can run the engine.

**Restarts after a reboot.** Docker's daemon starts containers again by their `restart` policy. Podman has no daemon, so with `restart` set to `always` or `unless-stopped`, Conn3x enables `podman-restart.service`, as root or with `systemctl --user` otherwise. If it can't, the apply says so.

**Rules.** `name` starts with a letter or digit and holds letters, digits and `_ . -`. Each port is `host:container`, optionally with an address in front and `/tcp`, `/udp` or `/sctp` after. Each volume is `source:destination`, where the source is an absolute host path or a volume name, with options from `ro`, `rw`, `z` and `Z`. `env` keys are variable names, and values can't hold line breaks.

**Changes.** Changing anything but `name` recreates the container. Changing `name` replaces the step, and `on_remove` decides what happens to the old container.

**Not yet.** Networks, health checks and resource limits aren't settings of this step.

## Removal

When you delete a `container` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the container running. `"delete"` removes it with `rm -f`. Its volumes stay either way.

## From Ansible

`conn3x convert ansible` turns `community.docker.docker_container` and `containers.podman.podman_container` tasks with `state: started` into `container` steps, with `engine` set to match. `published_ports`, `publish` and `ports` become `ports`; `volumes` and `volume` become `volumes`; `restart_policy` becomes `restart`; `env` and `command` carry over. A `command` written as one string with quotes or shell characters, any other `state`, and arguments the step doesn't have, such as `networks` or `healthcheck`, stay a TODO.
