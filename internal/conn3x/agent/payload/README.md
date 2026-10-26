# Agent payload

`scripts/build-agent.sh` writes the gzipped Linux agents here, and
`payload.go` embeds them into conn3x:

- `conn3x-agent-linux-amd64.gz`
- `conn3x-agent-linux-arm64.gz`

They are build output and never committed. This README keeps the directory
from being empty, so `go:embed` works in a build without them. Such a build
runs every host command through the shell.
