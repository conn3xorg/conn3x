#!/usr/bin/env sh
# Starts a throwaway Rocky Linux 10 container on 127.0.0.1:2222 that Conn3x
# can configure, with a fresh SSH key and its host key in ./known_hosts.
set -eu
cd "$(dirname "$0")"
engine=${ENGINE:-$(command -v podman >/dev/null 2>&1 && echo podman || echo docker)}

[ -f id_ed25519 ] || ssh-keygen -q -t ed25519 -N '' -C conn3x-try -f id_ed25519
$engine build -q -f Containerfile -t conn3x-try . >/dev/null
$engine rm -f conn3x-try >/dev/null 2>&1 || true
$engine run -d --name conn3x-try -p 127.0.0.1:2222:22 conn3x-try >/dev/null
$engine exec -i conn3x-try sh -c 'cat > /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys' < id_ed25519.pub

# Record the container's host key, so Conn3x can check it like any other host.
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if ssh-keyscan -p 2222 127.0.0.1 > known_hosts 2>/dev/null && [ -s known_hosts ]; then
    echo "Ready: a Rocky Linux 10 host on 127.0.0.1:2222. Now run: conn3x init && conn3x plan"
    exit 0
  fi
  sleep 1
done
echo "The container started, but SSH didn't answer on 127.0.0.1:2222." >&2
exit 1
