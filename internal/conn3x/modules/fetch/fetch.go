// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package fetch brings things onto a host: a checksummed download, an
// unpacked archive, or a git checkout.
package fetch

import (
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

var (
	sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitHex = regexp.MustCompile(`^[0-9a-f]{40}$`)
	gitRef    = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
	modeOctal = regexp.MustCompile(`^0?[0-7]{3,4}$`)
)

func absolute(label, p string) error {
	if !path.IsAbs(p) || strings.ContainsAny(p, "\r\n") {
		return fmt.Errorf("%s %q must be an absolute path", label, p)
	}
	return nil
}

func httpURL(u string) error {
	if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") || strings.ContainsAny(u, " \t\r\n") {
		return fmt.Errorf("url %q must be an http or https URL without spaces", u)
	}
	return nil
}

// Download is a file fetched from a URL and kept only if its checksum matches.
type Download struct {
	URL, Dest, SHA256  string
	Mode, Owner, Group string // mode defaults to 0644
}

// Validate checks a Download before anything reaches the host.
func (d Download) Validate() error {
	if err := httpURL(d.URL); err != nil {
		return err
	}
	if err := absolute("dest", d.Dest); err != nil {
		return err
	}
	if !sha256Hex.MatchString(d.SHA256) {
		return errors.New("sha256 must be 64 lowercase hex characters")
	}
	if d.Mode != "" && !modeOctal.MatchString(d.Mode) {
		return fmt.Errorf("mode %q must be octal, like \"0644\"", d.Mode)
	}
	return nil
}

// ReadDownload returns the SHA-256 of the file at dest, or "" if it is missing.
func ReadDownload(ctx context.Context, r modules.Runner, dest string) (string, error) {
	res, err := r.Run(ctx, fmt.Sprintf("if [ -f %[1]s ]; then sha256sum -- %[1]s; fi", ssh.Quote(dest)), nil)
	if err := check(res, err); err != nil {
		return "", err
	}
	sum, _, _ := strings.Cut(string(res.Stdout), " ")
	return strings.TrimSpace(sum), nil
}

// ApplyDownload fetches into a temporary file beside dest and moves it into
// place only once its checksum matches, so dest is never a partial or
// tampered file.
func ApplyDownload(ctx context.Context, r modules.Runner, d Download) error {
	if err := d.Validate(); err != nil {
		return err
	}
	mode := d.Mode
	if mode == "" {
		mode = "0644"
	}
	var owner strings.Builder
	if d.Owner != "" {
		fmt.Fprintf(&owner, "chown -- %s \"$tmp\"\n", ssh.Quote(d.Owner))
	}
	if d.Group != "" {
		fmt.Fprintf(&owner, "chgrp -- %s \"$tmp\"\n", ssh.Quote(d.Group))
	}
	script := fmt.Sprintf(`set -e
p=%[1]s
url=%[2]s
want=%[3]s
mkdir -p -- "$(dirname -- "$p")"
tmp=$(mktemp "$(dirname -- "$p")/.conn3x.XXXXXX")
trap 'rm -f -- "$tmp"' EXIT
if command -v curl >/dev/null 2>&1; then curl -fsSL --retry 3 -o "$tmp" -- "$url"
elif command -v wget >/dev/null 2>&1; then wget -q -O "$tmp" -- "$url"
else echo "neither curl nor wget is installed; add a package step for one first" >&2; exit 1; fi
got=$(sha256sum -- "$tmp" | cut -d' ' -f1)
if [ "$got" != "$want" ]; then echo "checksum mismatch for $url: got $got, want $want" >&2; exit 1; fi
chmod %[4]s "$tmp"
%[5]smv -f -- "$tmp" "$p"
trap - EXIT
if command -v restorecon >/dev/null 2>&1; then restorecon -- "$p" 2>/dev/null || true; fi`,
		ssh.Quote(d.Dest), ssh.Quote(d.URL), d.SHA256, mode, owner.String())
	res, err := r.Run(ctx, script, nil)
	return check(res, err)
}

// DeleteDownload removes the file.
func DeleteDownload(ctx context.Context, r modules.Runner, dest string) error {
	return file.Delete(ctx, r, dest)
}

// Archive is a tar or zip file on the host, unpacked into Dest. Creates is a
// path the archive puts in place; while it exists, nothing is unpacked.
type Archive struct{ Src, Dest, Creates string }

// Validate checks an Archive before anything reaches the host.
func (a Archive) Validate() error {
	for label, p := range map[string]string{"src": a.Src, "dest": a.Dest, "creates": a.Creates} {
		if err := absolute(label, p); err != nil {
			return err
		}
	}
	return nil
}

// ReadArchive reports whether the archive's creates path exists.
func ReadArchive(ctx context.Context, r modules.Runner, a Archive) (bool, error) {
	res, err := r.Run(ctx, "test -e "+ssh.Quote(a.Creates), nil)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

// ApplyArchive unpacks the archive: zip files with unzip, anything else with
// tar, which detects the compression itself.
func ApplyArchive(ctx context.Context, r modules.Runner, a Archive) error {
	if err := a.Validate(); err != nil {
		return err
	}
	script := fmt.Sprintf(`set -e
src=%[1]s
dest=%[2]s
test -f "$src" || { echo "$src does not exist" >&2; exit 1; }
mkdir -p -- "$dest"
case "$src" in
*.zip) command -v unzip >/dev/null 2>&1 || { echo "unzip is not installed; add a package step for it first" >&2; exit 1; }
  unzip -q -o "$src" -d "$dest" ;;
*) tar -xf "$src" -C "$dest" ;;
esac
test -e %[3]s || { echo "unpacked $src, but it did not create %[3]s" >&2; exit 1; }`,
		ssh.Quote(a.Src), ssh.Quote(a.Dest), ssh.Quote(a.Creates))
	res, err := r.Run(ctx, script, nil)
	return check(res, err)
}

// Git is a checkout of a repository at a branch, tag or full commit.
type Git struct {
	Repo, Dest string
	Ref        string // defaults to HEAD, the remote's default branch
}

// Validate checks a Git before anything reaches the host.
func (g Git) Validate() error {
	ok := false
	for _, scheme := range []string{"https://", "http://", "ssh://", "git@", "file://"} {
		ok = ok || strings.HasPrefix(g.Repo, scheme)
	}
	if !ok || strings.ContainsAny(g.Repo, " \t\r\n") {
		return fmt.Errorf("repo %q must be an https, ssh or git@ URL without spaces", g.Repo)
	}
	if err := absolute("dest", g.Dest); err != nil {
		return err
	}
	if g.Ref != "" && (!gitRef.MatchString(g.Ref) || strings.HasPrefix(g.Ref, "-")) {
		return fmt.Errorf("ref %q is not a branch, tag or commit", g.Ref)
	}
	return nil
}

func (g Git) ref() string {
	if g.Ref == "" {
		return "HEAD"
	}
	return g.Ref
}

// resolve finds ref's commit in "git ls-remote" output. A full commit hash
// resolves to itself; for an annotated tag, the commit it points at wins.
func resolve(lsRemote, ref string) (string, error) {
	if commitHex.MatchString(ref) {
		return ref, nil
	}
	found := ""
	for _, line := range strings.Split(lsRemote, "\n") {
		sha, name, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if !ok {
			continue
		}
		switch name {
		case "refs/tags/" + ref + "^{}":
			return sha, nil
		case ref, "refs/heads/" + ref, "refs/tags/" + ref:
			if found == "" {
				found = sha
			}
		}
	}
	if found == "" {
		return "", fmt.Errorf("the remote has no branch or tag %q (commits must be given in full)", ref)
	}
	return found, nil
}

// Remote returns the commit the ref points at on the remote.
func Remote(ctx context.Context, r modules.Runner, g Git) (string, error) {
	if commitHex.MatchString(g.ref()) {
		return g.ref(), nil
	}
	res, err := r.Run(ctx, fmt.Sprintf("%s\ngit ls-remote -- %s %s", gitInstalled, ssh.Quote(g.Repo), ssh.Quote(g.ref())), nil)
	if err := check(res, err); err != nil {
		return "", err
	}
	return resolve(string(res.Stdout), g.ref())
}

const gitInstalled = `command -v git >/dev/null 2>&1 || { echo "git is not installed; add a package step for it first" >&2; exit 1; }`

// Checkout returns the commit checked out at dest, or "" if there is none.
func Checkout(ctx context.Context, r modules.Runner, dest string) (string, error) {
	res, err := r.Run(ctx, fmt.Sprintf("if [ -d %[1]s/.git ]; then git -C %[1]s rev-parse HEAD; fi", ssh.Quote(dest)), nil)
	if err := check(res, err); err != nil {
		return "", err
	}
	return strings.TrimSpace(string(res.Stdout)), nil
}

// ApplyGit clones the repository if dest has none, fetches, and checks out
// commit, detached, discarding local changes to tracked files.
func ApplyGit(ctx context.Context, r modules.Runner, g Git, commit string) error {
	if err := g.Validate(); err != nil {
		return err
	}
	if !commitHex.MatchString(commit) {
		return fmt.Errorf("%q is not a commit", commit)
	}
	script := fmt.Sprintf(`set -e
%[1]s
dest=%[2]s
if [ ! -d "$dest/.git" ]; then git clone --quiet --no-checkout -- %[3]s "$dest"; fi
git -C "$dest" remote set-url origin %[3]s
git -C "$dest" cat-file -e %[4]s^{commit} 2>/dev/null || git -C "$dest" fetch --quiet --tags origin
git -C "$dest" cat-file -e %[4]s^{commit} 2>/dev/null || git -C "$dest" fetch --quiet origin %[4]s
git -C "$dest" checkout --quiet --force --detach %[4]s`, gitInstalled, ssh.Quote(g.Dest), ssh.Quote(g.Repo), commit)
	res, err := r.Run(ctx, script, nil)
	return check(res, err)
}

func check(res ssh.Result, err error) error {
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return errors.New(strings.TrimSpace(string(res.Stderr) + string(res.Stdout)))
	}
	return nil
}
