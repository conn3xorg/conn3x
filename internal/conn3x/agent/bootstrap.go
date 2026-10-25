// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Options says how Attach may get an agent running on a host.
type Options struct {
	// Upload lets Attach copy the agent to the host when no verified copy
	// is cached there. Plans leave it off, so they never write to a host.
	Upload bool
	// Version goes into the cached file's name, beside the checksum.
	Version string
	// Payload returns the gzipped agent for a GOARCH and the sha256 of the
	// binary inside. Nil means Embedded.
	Payload func(arch string) (gz []byte, sum [32]byte, err error)
}

// goarch maps what uname -m says to the agent built for it.
var goarch = map[string]string{"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}

// helpers are the shell functions every bootstrap script uses. A directory
// is usable only if it is ours, private and not a symlink.
const helpers = `umask 077
sum256() { { sha256sum "$1" || shasum -a 256 "$1"; } 2>/dev/null | cut -d' ' -f1; }
usable() { [ -d "$1" ] && [ ! -L "$1" ] && [ -O "$1" ] && case $(ls -ld "$1") in drwx------*) true ;; *) false ;; esac; }
`

// probeScript reports the host's architecture, whether fapolicyd is
// active, whether gunzip exists and, for each candidate cache directory
// that is usable, the checksum of a cached agent and, when creating is
// allowed, whether a file there can be executed. It writes nothing unless
// create is set.
const probeScript = helpers + `m=$(uname -m)
echo "arch $m"
case $m in x86_64|amd64) name=%s ;; aarch64|arm64) name=%s ;; *) exit 0 ;; esac
[ -n "$name" ] || exit 0
if systemctl is-active --quiet fapolicyd 2>/dev/null; then echo fapolicyd; exit 0; fi
command -v gunzip >/dev/null 2>&1 && echo gunzip
uid=$(id -u)
for d in "${XDG_CACHE_HOME:-$HOME/.cache}/conn3x" "$HOME/.conn3x" "/var/tmp/conn3x-$uid" "/dev/shm/conn3x-$uid"; do
  [ -n "%s" ] && mkdir -p "$d" 2>/dev/null
  usable "$d" || continue
  s=; [ -f "$d/$name" ] && s=$(sum256 "$d/$name")
  x=-
  if [ -n "%[3]s" ] && c=$(mktemp "$d/.canary.XXXXXX" 2>/dev/null); then
    printf '#!/bin/sh\n' >"$c" && chmod 700 "$c" && "$c" 2>/dev/null && x=exec
    rm -f "$c"
  fi
  printf 'dir %%s %%s %%s\n' "${s:--}" "$x" "$d"
done
`

// uploadScript writes stdin to a temp file, checks it and only then
// renames it into place, so a cut-short or damaged upload never becomes
// the cached agent. It then keeps the new agent and the newest other one.
const uploadScript = helpers + `d=%s name=%s want=%s
usable "$d" || { echo "$d is not a private directory" >&2; exit 1; }
if command -v flock >/dev/null 2>&1; then exec 9>>"$d/.lock" && flock -w 120 9 || exit 1; fi
find "$d" -maxdepth 1 -name '.agent.*' -mmin +60 -exec rm -f {} + 2>/dev/null
t=$(mktemp "$d/.agent.XXXXXX") || exit 1
trap 'rm -f "$t"' EXIT
%s >"$t" || { echo "the upload was cut short" >&2; exit 1; }
got=$(sum256 "$t")
[ "$got" = "$want" ] || { echo "checksum mismatch: got ${got:-nothing}" >&2; exit 1; }
chmod 700 "$t" && mv -f "$t" "$d/$name" || exit 1
trap - EXIT
ls -t "$d" | grep '^agent-' | grep -vxF "$name" | tail -n +2 | while IFS= read -r f; do rm -f "$d/$f"; done
`

// startScript checks the directory again, right before running from it.
const startScript = helpers + `d=%s
usable "$d" || { echo "$d is not a private directory" >&2; exit 126; }
exec "$d"/%s`

type build struct {
	gz   []byte
	sum  string
	name string
}

type probed struct {
	arch      string
	fapolicyd bool
	gunzip    bool
	dirs      []probedDir
}

type probedDir struct {
	path string
	sum  string // "-" when nothing is cached
	exec bool
}

// Attach starts an agent on the host c is connected to and returns a
// client for it. It uses a verified copy cached on the host, or uploads one
// when o.Upload allows. Whenever the agent can't run there it returns an
// error wrapping ErrUnavailable, and the caller carries on with the shell.
func Attach(ctx context.Context, c *ssh.Client, o Options) (*Client, error) {
	payload := o.Payload
	if payload == nil {
		payload = Embedded
	}
	builds := map[string]build{}
	for _, arch := range []string{"amd64", "arm64"} {
		gz, sum, err := payload(arch)
		if err != nil {
			continue
		}
		hexSum := hex.EncodeToString(sum[:])
		builds[arch] = build{gz: gz, sum: hexSum, name: "agent-" + cleanVersion(o.Version) + "-" + hexSum[:12]}
	}
	if len(builds) == 0 {
		return nil, fmt.Errorf("%w: this build of conn3x has none", ErrUnavailable)
	}

	create := ""
	if o.Upload {
		create = "1"
	}
	res, err := c.Run(ctx, fmt.Sprintf(probeScript, ssh.Quote(builds["amd64"].name), ssh.Quote(builds["arm64"].name), create), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: probing the host: %w", ErrUnavailable, err)
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("%w: probing the host: exit %d: %s", ErrUnavailable, res.ExitCode, bytes.TrimSpace(res.Stderr))
	}
	p := parseProbe(res.Stdout)
	arch, known := goarch[p.arch]
	b, ok := builds[arch]
	switch {
	case !known:
		return nil, fmt.Errorf("%w: there is no agent for %s hosts", ErrUnavailable, p.arch)
	case !ok:
		return nil, fmt.Errorf("%w: this build of conn3x has no agent for linux/%s", ErrUnavailable, arch)
	case p.fapolicyd:
		return nil, fmt.Errorf("%w: fapolicyd is active and would block it", ErrUnavailable)
	}

	// A verified copy already on the host wins.
	var failures []string
	for _, d := range p.dirs {
		if d.sum != b.sum {
			continue
		}
		a, err := start(ctx, c, d.path, b.name)
		if err == nil {
			return a, nil
		}
		failures = append(failures, err.Error())
	}
	if !o.Upload {
		failures = append(failures, "no verified copy is cached on the host, and only an apply uploads one")
		return nil, fmt.Errorf("%w: %s", ErrUnavailable, strings.Join(failures, "; "))
	}

	gz, unpack := b.gz, "gunzip -c"
	if !p.gunzip {
		if gz, err = gunzip(b.gz); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
		}
		unpack = "cat"
	}
	for _, d := range p.dirs {
		if !d.exec {
			continue
		}
		res, err := c.Run(ctx, fmt.Sprintf(uploadScript, ssh.Quote(d.path), ssh.Quote(b.name), b.sum, unpack), gz)
		switch {
		case err != nil:
			failures = append(failures, fmt.Sprintf("uploading to %s: %v", d.path, err))
			continue
		case res.ExitCode != 0:
			failures = append(failures, fmt.Sprintf("uploading to %s: %s", d.path, bytes.TrimSpace(res.Stderr)))
			continue
		}
		a, err := start(ctx, c, d.path, b.name)
		if err == nil {
			return a, nil
		}
		failures = append(failures, err.Error())
	}
	if len(failures) == 0 {
		failures = append(failures, "no cache directory on the host is private and allows running programs")
	}
	return nil, fmt.Errorf("%w: %s", ErrUnavailable, strings.Join(failures, "; "))
}

// start runs the agent cached in dir and waits for its hello.
func start(ctx context.Context, c *ssh.Client, dir, name string) (*Client, error) {
	p, err := c.Start(ctx, "exec /bin/sh -c "+ssh.Quote(fmt.Sprintf(startScript, ssh.Quote(dir), ssh.Quote(name))))
	if err != nil {
		return nil, fmt.Errorf("starting the agent in %s: %w", dir, err)
	}
	a, err := NewClient(ctx, p)
	if err != nil {
		if msg := bytes.TrimSpace(p.Stderr()); len(msg) > 0 {
			return nil, fmt.Errorf("starting the agent in %s: %v: %s", dir, err, msg)
		}
		return nil, fmt.Errorf("starting the agent in %s: %v", dir, err)
	}
	return a, nil
}

func parseProbe(out []byte) probed {
	var p probed
	for _, line := range strings.Split(string(out), "\n") {
		switch f := strings.SplitN(line, " ", 4); {
		case f[0] == "arch" && len(f) > 1:
			p.arch = strings.Join(f[1:], " ")
		case f[0] == "fapolicyd":
			p.fapolicyd = true
		case f[0] == "gunzip":
			p.gunzip = true
		case f[0] == "dir" && len(f) == 4:
			p.dirs = append(p.dirs, probedDir{sum: f[1], exec: f[2] == "exec", path: f[3]})
		}
	}
	return p
}

func gunzip(gz []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// cleanVersion keeps a version safe to put in a file name.
func cleanVersion(v string) string {
	if v == "" {
		return "dev"
	}
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(".+-", r) {
			return r
		}
		return '_'
	}, v)
}
