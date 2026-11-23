Use `container_network` to give containers a network of their own, where they reach each other by name and nothing else on the host joins by accident. It's `community.docker.docker_network`, on Docker or Podman. A `container` step joins it with `networks`.

## Example usage

A network for an app and its database, with a fixed subnet:

```hcl
step "app_network" {
  container_network {
    name   = "app"
    subnet = "10.89.0.0/24"
  }
}
```

The containers on it:

```hcl
step "web" {
  container {
    name     = "web"
    image    = "docker.io/library/nginx:1.30"
    networks = ["app"]
    ports    = ["8080:80"]
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x runs `docker network inspect`, or Podman's, and compares the driver, and the subnet if you set one. Docker and Podman print a network differently, and Conn3x reads both. A network deleted by hand shows as out of sync, and the next apply makes it again.

**Changes.** A network's driver and subnet can't change in place, so a difference means Conn3x removes the network and makes it again. The engine refuses while a container is on it, and the apply says so: remove the container, or change its step too, so it's made again on the new network.

**Rules.** `driver` is `bridge`, `macvlan` or `ipvlan`. `subnet` is a CIDR block written as the engines print it, such as `10.89.0.0/24`, not `10.89.0.1/24`.

**Not yet.** Swarm's overlay networks, more than one subnet, gateways and IP ranges, and driver options such as macvlan's `parent` aren't settings of this step.

## Removal

`on_remove = "forget"`, the default, leaves the network. `on_remove = "delete"` removes it with `network rm`. The engine won't remove a network a container is on, so remove the containers first: put their steps after this one, and Conn3x removes them in reverse.

## From Ansible

`conn3x convert ansible` turns `community.docker.docker_network` and `containers.podman.podman_network` tasks with `state: present` into `container_network` steps, with `engine` set to match. `name` and `driver` carry over. Docker's `ipam_config` with one entry that sets only `subnet`, and Podman's `subnet`, become `subnet`. More than one subnet, a gateway or IP range, Swarm's overlay driver, any other `state` and arguments the step doesn't have stay a TODO.
