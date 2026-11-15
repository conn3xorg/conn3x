# Test host images

Each directory builds a host the end-to-end tests apply circuits to: systemd as PID 1, sshd enabled, and an empty `/root/.ssh` for the test's key. `test/e2e` builds them locally.

Rocky Linux 10, Debian 13 and Ubuntu 24.04 are also published, signed, as `ghcr.io/conn3xorg/test-rocky10`, `test-debian13` and `test-ubuntu2404`, for amd64 and arm64, by `.github/workflows/test-images.yml`. Use them to apply a circuit in your own `conn3x test` runs, when its steps start services:

```sh
podman run -d --name web1 --systemd=always -p 127.0.0.1:2222:22 ghcr.io/conn3xorg/test-rocky10
podman exec -i web1 sh -c 'cat > /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys' < ~/.ssh/id_ed25519.pub
```

Then point the circuit's `ssh` block at `127.0.0.1` port `2222` as `root`. Each test should get a new container: `podman rm -f web1` when it's done.

They're for throwaway containers only. Root logs in with any key you add, and nothing else about them is hardened.
