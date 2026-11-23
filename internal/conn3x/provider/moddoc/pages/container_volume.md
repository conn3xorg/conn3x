Use `container_volume` to make a named volume before a container mounts it, so its data has a name you chose and outlives the container. It's `community.docker.docker_volume`, on Docker or Podman. A `container` step mounts it in `volumes`, as `name:/path`.

## Example usage

A volume for a database's data, and the container that mounts it:

```hcl
step "pgdata" {
  container_volume {
    name = "pgdata"
  }
}
```

```hcl
step "db" {
  container {
    name    = "db"
    image   = "docker.io/library/postgres:17"
    volumes = ["pgdata:/var/lib/postgresql/data"]
    env     = { POSTGRES_PASSWORD = "change-me" }
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x runs `docker volume inspect`, or Podman's. `in_sync` is true when the volume is there with this `driver`. A volume deleted by hand shows as out of sync, and the next apply makes it again, empty.

**Drivers.** A volume's driver can't change without removing it and its data. Conn3x won't do that for you: if the volume is there with another driver, the apply stops and says how to remove it.

**Not yet.** Driver options and labels aren't settings of this step.

## Removal

`on_remove = "forget"`, the default, leaves the volume and its data. `on_remove = "delete"` removes both with `volume rm`. The engine won't remove a volume a container uses, so remove the container first: put its step after this one, and Conn3x removes them in reverse.

## From Ansible

`conn3x convert ansible` turns `community.docker.docker_volume` and `containers.podman.podman_volume` tasks with `state: present` into `container_volume` steps, with `engine` set to match. `name`, or Docker's `volume_name`, and `driver` carry over. Driver options, labels, any other `state` and arguments the step doesn't have stay a TODO.
