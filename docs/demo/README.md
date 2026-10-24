# README demo

`demo.tape` records `.github/assets/demo.gif` with [VHS](https://github.com/charmbracelet/vhs).

To re-record it:

1. Build conn3x: `scripts/build-conn3x.sh /tmp/conn3x-demo/conn3x`
2. Start a host: `podman run -d --rm --name conn3x-demo --systemd=always -p 127.0.0.1:2222:22 <rocky10 image from test/images/rocky10>`
3. In `/tmp/conn3x-demo`, create `id_ed25519`, install its public key as root's `authorized_keys` in the container, and write `known_hosts` with `ssh-keyscan -p 2222 127.0.0.1`.
4. Copy `web.circuit.hcl` there, run `conn3x init`, then `vhs demo.tape` from that directory.
