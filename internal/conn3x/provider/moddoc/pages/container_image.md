Use `container_image` to have an image on the host before a container needs it: pulled once, kept there, and pulled again if someone removes it. It's `community.docker.docker_image` with `source: pull`, on Docker or Podman.

## Example usage

Pull nginx ahead of the container that runs it, and remove it with the step:

```hcl
step "nginx_image" {
  container_image {
    name      = "docker.io/library/nginx"
    tag       = "1.30"
    on_remove = "delete"
  }
}
```

Pin an image by digest, on Podman:

```hcl
step "worker_image" {
  container_image {
    name   = "ghcr.io/example/worker@sha256:3f1d2a8c0b9e7f6a5d4c3b2a1908f7e6d5c4b3a29180f7e6d5c4b3a2918070f6"
    engine = "podman"
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x runs `docker image inspect`, or Podman's, for the image. `in_sync` is true when it's on the host. An image removed by hand shows as out of sync, and the next apply pulls it again.

**Tags.** A tag that now points at a newer image doesn't pull it: the image on the host is what's kept. To roll forward, change `tag`, or pin a digest in `name`. Changing `name` or `tag` replaces the step, and `on_remove` decides whether the old image stays.

**Writing the name.** Write it as the `container` step writes its `image`, such as `docker.io/library/nginx:1.30`, so both name the same image. Set the tag in `name` or in `tag`, not both.

**Not yet.** Building an image, loading one from an archive and logging in to a registry aren't settings of this step.

## Removal

`on_remove = "forget"`, the default, leaves the image. `on_remove = "delete"` removes it with `image rm`. The engine won't remove an image a container uses, so remove the container first: put its step after this one, and Conn3x removes them in reverse.

## From Ansible

`conn3x convert ansible` turns `community.docker.docker_image` and `containers.podman.podman_image` tasks with `state: present` into `container_image` steps, with `engine` set to match. `name` and `tag` carry over; a tag in `name` wins, as it does in Ansible. `source: build`, `source: load`, `source: local`, a `build` block, `pull: false`, any other `state` and arguments the step doesn't have stay a TODO.
