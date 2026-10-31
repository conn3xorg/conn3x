// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package sshkey

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // OpenSSH's hashed host format is defined with HMAC-SHA1.
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	gossh "golang.org/x/crypto/ssh"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// SystemKnownHosts is the file ssh reads for every user on a host.
const SystemKnownHosts = "/etc/ssh/ssh_known_hosts"

var hostName = regexp.MustCompile(`^(\[[^\s\[\],*?!|#@]+\]:[0-9]+|[^\s\[\],*?!|#@]+)$`)

// ValidateKnownHost checks a host name and, when set, its key. The name has
// to be one literal, lowercase host, because ssh looks hosts up in lowercase
// and a pattern would match hosts nobody named.
func ValidateKnownHost(host, key string) error {
	if !hostName.MatchString(host) {
		return fmt.Errorf("host %q must be one host name or address, or [host]:port, with no patterns", host)
	}
	if host != strings.ToLower(host) {
		return fmt.Errorf("host %q must be lowercase, the way ssh looks it up", host)
	}
	if key == "" {
		return nil
	}
	_, _, err := parseHostKey(key)
	return err
}

// parseHostKey reads "type base64 [comment]" and returns the type and data.
func parseHostKey(key string) (string, string, error) {
	f := strings.Fields(key)
	if strings.ContainsAny(key, "\r\n") || len(f) < 2 {
		return "", "", fmt.Errorf("key must be one line: the key type, the key and an optional comment, without the host name")
	}
	raw, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil {
		return "", "", fmt.Errorf("not a valid public key: %w", err)
	}
	pub, err := gossh.ParsePublicKey(raw)
	if err != nil {
		return "", "", fmt.Errorf("not a valid public key: %w", err)
	}
	if pub.Type() != f[0] {
		return "", "", fmt.Errorf("key says %s but holds a %s key", f[0], pub.Type())
	}
	return f[0], f[1], nil
}

// otherNames reports whether a known_hosts names field lists host, and what
// the field would hold without it. Wildcards and negations aren't entries for
// one host, so they don't count. A hashed name holds one host.
func otherNames(names, host string) (bool, string) {
	if strings.HasPrefix(names, "|1|") {
		p := strings.Split(names, "|")
		if len(p) != 4 {
			return false, ""
		}
		salt, err1 := base64.StdEncoding.DecodeString(p[2])
		want, err2 := base64.StdEncoding.DecodeString(p[3])
		if err1 != nil || err2 != nil {
			return false, ""
		}
		mac := hmac.New(sha1.New, salt)
		mac.Write([]byte(host))
		return hmac.Equal(mac.Sum(nil), want), ""
	}
	var rest []string
	found := false
	for _, n := range strings.Split(names, ",") {
		if strings.EqualFold(n, host) {
			found = true
		} else {
			rest = append(rest, n)
		}
	}
	return found, strings.Join(rest, ",")
}

// EditKnownHosts returns known_hosts content with host's key present or
// absent. A host has one key per type, so a different key of the same type is
// replaced and a key of another type stays. With no key, absent removes all
// the host's keys. Other hosts sharing a line keep it. Comments, @cert-authority
// and @revoked lines stay as they are.
func EditKnownHosts(content, host, key string, present bool) (string, error) {
	if err := ValidateKnownHost(host, key); err != nil {
		return "", err
	}
	var wantType, wantData string
	if key != "" {
		wantType, wantData, _ = parseHostKey(key)
	}
	var lines, kept []string
	if content != "" {
		lines = strings.Split(strings.TrimSuffix(content, "\n"), "\n")
	}
	found, changed := false, false
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 3 || strings.HasPrefix(f[0], "#") || strings.HasPrefix(f[0], "@") {
			kept = append(kept, l)
			continue
		}
		listed, rest := otherNames(f[0], host)
		same := f[1] == wantType && f[2] == wantData
		drop := listed && ((present && f[1] == wantType && !same) || (!present && (key == "" || same)))
		found = found || (listed && same)
		if !drop {
			kept = append(kept, l)
			continue
		}
		changed = true
		if rest != "" {
			kept = append(kept, rest+strings.TrimPrefix(strings.TrimLeft(l, " \t"), f[0]))
		}
	}
	if present && !found {
		kept = append(kept, host+" "+strings.TrimSpace(key))
		changed = true
	}
	if !changed {
		return content, nil
	}
	if len(kept) == 0 {
		return "", nil
	}
	return strings.Join(kept, "\n") + "\n", nil
}

// LocateKnownHosts finds a user's ~/.ssh/known_hosts from the user database.
func LocateKnownHosts(ctx context.Context, r modules.Runner, user string) (Location, error) {
	loc, err := Locate(ctx, r, user)
	loc.File = loc.Dir + "/known_hosts"
	return loc, err
}

// ApplyKnownHost makes host's key present or absent in a user's known_hosts.
// As in Apply, everything runs as the user, so a symlink they planted gets
// them nothing they couldn't already reach. An existing ~/.ssh keeps its mode;
// a new one gets 0700. The file keeps its mode, and starts at 0644 like the one
// ssh itself would leave under the usual umask. A link at the file's path is
// replaced, not followed.
func ApplyKnownHost(ctx context.Context, r modules.Runner, loc Location, host, key string, present bool) error {
	current, err := Read(ctx, r, loc)
	if err != nil {
		return err
	}
	edited, err := EditKnownHosts(current, host, key, present)
	if err != nil {
		return err
	}
	if edited == current {
		return nil
	}
	script := fmt.Sprintf(`set -e
d=%[1]s
f=%[2]s
mkdir -p -m 0700 -- "$d"
mode=0644
if [ -f "$f" ] && [ ! -L "$f" ]; then mode=$(stat -c %%a -- "$f"); fi
tmp=$(mktemp "$d/.conn3x.XXXXXX")
trap 'rm -f -- "$tmp"' EXIT
cat > "$tmp"
chmod "$mode" "$tmp"
mv -f -- "$tmp" "$f"
trap - EXIT
if command -v restorecon >/dev/null 2>&1; then restorecon -- "$d" "$f" 2>/dev/null || true; fi`,
		ssh.Quote(loc.Dir), ssh.Quote(loc.File))
	res, err := r.Run(ctx, modules.AsUser(loc.Owner, script), []byte(edited))
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("writing %s as %s: %s", loc.File, loc.Owner, strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}
