// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package file manages the content, mode and ownership of a regular file.
package file

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Desired is the file as it should be. An empty Owner or Group leaves it as is.
type Desired struct {
	Path    string
	Content string
	Mode    string // octal, like "0644"
	Owner   string
	Group   string
	// ValidateCommand, when set, checks the new content before it replaces
	// the file. %s stands for the temporary file's path.
	ValidateCommand string
	// Backup copies the file as it was to Path plus BackupSuffix and the
	// time in UTC, with its mode and owner, just before replacing it.
	Backup bool
}

// BackupSuffix starts a backup copy's name, before the time it was made:
// /etc/ssh/sshd_config.conn3x-20261118T130501Z.
const BackupSuffix = ".conn3x-"

// Actual is the file as it is.
type Actual struct {
	Exists  bool
	Content string
	Mode    string // four-digit octal
	Owner   string
	Group   string
}

var modePattern = regexp.MustCompile(`^[0-7]{4}$`)

// Validate checks a Desired before anything runs on a host.
func (d Desired) Validate() error {
	if d.Path == "" || !path.IsAbs(d.Path) {
		return fmt.Errorf("path %q must be absolute", d.Path)
	}
	if !modePattern.MatchString(d.Mode) {
		return fmt.Errorf("mode %q must be four octal digits, like \"0644\"", d.Mode)
	}
	if d.ValidateCommand != "" && !strings.Contains(d.ValidateCommand, "%s") {
		return fmt.Errorf("validate %q must contain %%s, which stands for the file to check", d.ValidateCommand)
	}
	return nil
}

// ValidateError is a validate command that rejected the new content. The
// file was left as it was.
type ValidateError struct {
	Output string // what the command printed, stdout and stderr together
}

func (e *ValidateError) Error() string {
	if e.Output == "" {
		return "validate rejected the new content; the file was left as it was"
	}
	return "validate rejected the new content; the file was left as it was:\n" + e.Output
}

// NormalizeMode returns mode as four octal digits.
func NormalizeMode(mode string) string {
	m := strings.TrimLeft(mode, "0")
	return fmt.Sprintf("%04s", m)
}

const notRegular = 3

// MaxRead is the largest file Read returns, the same as the agent's limit.
// A host, or a user who owns a managed file, could otherwise fill the
// controller's memory with one that's huge or sparse.
var MaxRead = 255 << 20

// unreadable is the exit code for a file the login user can't read. Without
// it, base64's failure is lost in the pipe and the file reads as empty.
const unreadable = 4

// validateFailed is the exit code for a validate command that rejected the
// new content.
const validateFailed = 5

// Read reports the file's current state. A missing file is not an error.
// A runner that is a modules.FileReader answers natively when it can.
//
// via are routes walked before p's own, for a p that was worked out from
// another path: whoever owns the way to that one reads this one.
func Read(ctx context.Context, r modules.Runner, p string, via ...modules.Route) (Actual, error) {
	if fr, ok := r.(modules.FileReader); ok && len(via) == 0 {
		st, err := fr.ReadFile(ctx, p)
		switch {
		case err == nil && !st.Exists:
			return Actual{}, nil
		case err == nil && !st.Regular:
			return Actual{}, notRegularError(p)
		case err == nil:
			return Actual{Exists: true, Content: string(st.Content), Mode: fmt.Sprintf("%04o", st.Mode), Owner: st.Owner, Group: st.Group}, nil
		case !errors.Is(err, errors.ErrUnsupported):
			return Actual{}, err
		}
	}
	q := ssh.Quote(p)
	script := modules.Settled + fmt.Sprintf(`p=%s
route_settled "$p" || { echo missing; exit 0; }
[ -e "$p" ] || [ -L "$p" ] || { echo missing; exit 0; }
[ -f "$p" ] || exit %d
[ -r "$p" ] || { id -un; exit %d; }
echo present
stat -c '%%a %%U %%G' -- "$p" 2>/dev/null || stat -f '%%Lp %%Su %%Sg' "$p"
head -c %d < "$p" | base64 | tr -d '\n'`, q, notRegular, unreadable, MaxRead+1)
	res, err := run(ctx, r, modules.Guard(script, append(via, modules.Follow(p))...), nil)
	if err != nil {
		if res.ExitCode == notRegular {
			return Actual{}, notRegularError(p)
		}
		if res.ExitCode == unreadable {
			return Actual{}, fmt.Errorf("%s exists but can't be read by %s; give it to that user, or if a new release moved it, run conn3x apply -refresh=false once", p, strings.TrimSpace(string(res.Stdout)))
		}
		return Actual{}, err
	}
	lines := strings.SplitN(string(res.Stdout), "\n", 3)
	if lines[0] == "missing" {
		return Actual{}, nil
	}
	if len(lines) < 2 {
		return Actual{}, fmt.Errorf("reading %s: unexpected output %q", p, res.Stdout)
	}
	meta := strings.Fields(lines[1])
	if len(meta) != 3 {
		return Actual{}, fmt.Errorf("reading %s: unexpected stat output %q", p, lines[1])
	}
	var encoded string
	if len(lines) == 3 {
		encoded = lines[2]
	}
	content, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return Actual{}, fmt.Errorf("reading %s: %w", p, err)
	}
	if len(content) > MaxRead {
		return Actual{}, fmt.Errorf("%s is over %d MiB, the most a file step reads", p, MaxRead>>20)
	}
	return Actual{
		Exists:  true,
		Content: string(content),
		Mode:    NormalizeMode(meta[0]),
		Owner:   meta[1],
		Group:   meta[2],
	}, nil
}

// Exists reports whether a regular file is at p, without reading it, so a
// file the login user can't read still counts. Something else at the path
// is an error, as it is for Read.
func Exists(ctx context.Context, r modules.Runner, p string) (bool, error) {
	res, err := run(ctx, r, modules.Guard(modules.Settled+fmt.Sprintf(`p=%s
route_settled "$p" || { echo missing; exit 0; }
[ -e "$p" ] || [ -L "$p" ] || { echo missing; exit 0; }
[ -f "$p" ] || exit %d
echo present`, ssh.Quote(p), notRegular), modules.Follow(p)), nil)
	if err != nil {
		if res.ExitCode == notRegular {
			return false, notRegularError(p)
		}
		return false, err
	}
	return strings.TrimSpace(string(res.Stdout)) == "present", nil
}

func notRegularError(p string) error {
	return fmt.Errorf("%s exists but is not a regular file", p)
}

// NeedsChange reports whether Apply would change anything.
func NeedsChange(d Desired, a Actual) bool {
	return !a.Exists ||
		a.Content != d.Content ||
		NormalizeMode(d.Mode) != a.Mode ||
		(d.Owner != "" && d.Owner != a.Owner) ||
		(d.Group != "" && d.Group != a.Group)
}

// Apply writes the file atomically: a temporary file in the same directory
// gets the content, mode and ownership, passes the validate command if there
// is one, then replaces the target in one rename. The content is flushed to
// disk before the rename and the directory after it, so a power cut leaves
// the old file or the new one, never an empty one. On SELinux hosts the result is relabelled for its final path.
// via is as for Read.
func Apply(ctx context.Context, r modules.Runner, d Desired, via ...modules.Route) error {
	if err := d.Validate(); err != nil {
		return err
	}
	script := fmt.Sprintf(`set -e
p=%s
mkdir -p -- "$(dirname -- "$p")"
tmp=$(mktemp "$(dirname -- "$p")/.conn3x.XXXXXX")
trap 'rm -f -- "$tmp"' EXIT
cat > "$tmp"
chmod %s "$tmp"
%s%s%s`+SyncFile+`
`+Replace+`
trap - EXIT
`+SyncDir+`
if command -v restorecon >/dev/null 2>&1; then restorecon -- "$p" 2>/dev/null || true; fi`,
		ssh.Quote(d.Path), NormalizeMode(d.Mode), Ownership(d.Owner, d.Group), validateScript(d.ValidateCommand), backupScript(d.Backup))
	res, err := run(ctx, r, modules.GuardWrite(script, modules.Write{Owner: d.Owner, Group: d.Group, Path: d.Path}, append(via, modules.Parent(d.Path))...), []byte(d.Content))
	if err != nil && res.ExitCode == validateFailed {
		return &ValidateError{Output: strings.TrimSpace(string(res.Stderr))}
	}
	return err
}

// backupScript copies "$p", when it's there, to its backup name once the
// new content has passed validate, so a refused edit leaves no copy. A
// copy that fails stops the write: the old file stays, uncopied but whole.
func backupScript(backup bool) string {
	if !backup {
		return ""
	}
	return `if [ -f "$p" ]; then
  b="$p` + BackupSuffix + `$(date -u +%Y%m%dT%H%M%SZ)"
  [ ! -e "$b" ] || { echo "$b is already there" >&2; exit 1; }
  cp -p -- "$p" "$b"
fi
`
}

// validateScript runs the validate command on "$tmp" once it has its final
// mode and owner, and stops before the rename if the command fails. The
// command sits on lines of its own, so a trailing comment can't swallow the
// rest of the script. Its output goes to stderr only when it fails.
func validateScript(cmd string) string {
	if cmd == "" {
		return ""
	}
	return fmt.Sprintf(`validate_out=$( {
%s
} 2>&1 ) && validate_rc=0 || validate_rc=$?
[ "$validate_rc" -eq 0 ] || { printf '%%s\n' "$validate_out" >&2; exit %d; }
`, strings.ReplaceAll(cmd, "%s", `"$tmp"`), validateFailed)
}

// Ownership is the script that gives "$tmp" its owner and group before it
// replaces "$p". An empty owner or group keeps the one "$p" has now, since
// "$tmp" belongs to whoever ran mktemp, often root through become. Keeping
// it is best effort: a login user can't give a file to someone else.
//
// In a sticky directory, like /tmp, what's at "$p" may be a file someone
// put there first, and keeping its owner would hand them the new content.
// So root keeps nothing from a file there that isn't root's, the login
// user's or the owner asked for: it stops, and says to set both.
func Ownership(owner, group string) string {
	var b strings.Builder
	if owner == "" || group == "" {
		b.WriteString(modules.Settled + "route_hint='; set owner and group, or remove it first'\n")
		if owner == "" {
			b.WriteString("route_settled \"$p\" || true\n")
		} else {
			fmt.Fprintf(&b, "[ \"$(stat -c %%u -- \"$p\" 2>/dev/null)\" = \"$(id -u -- %s 2>/dev/null)\" ] || route_settled \"$p\" || true\n", ssh.Quote(owner))
		}
		b.WriteString(`if [ -e "$p" ]; then
  ids=$(stat -c '%u %g' -- "$p" 2>/dev/null || stat -f '%u %g' "$p")
`)
		if owner == "" {
			b.WriteString("  chown -- \"${ids% *}\" \"$tmp\" 2>/dev/null || true\n")
		}
		if group == "" {
			b.WriteString("  chgrp -- \"${ids#* }\" \"$tmp\" 2>/dev/null || true\n")
		}
		b.WriteString("fi\n")
	}
	if owner != "" {
		fmt.Fprintf(&b, "[ -n \"${CONN3X_ROUTE_OWN:-}\" ] || chown -- %s \"$tmp\"\n", ssh.Quote(owner))
	}
	if group != "" {
		fmt.Fprintf(&b, "[ -n \"${CONN3X_ROUTE_OWN:-}\" ] || chgrp -- %s \"$tmp\"\n", ssh.Quote(group))
	}
	return b.String()
}

// Replace moves "$tmp" over "$p". -T keeps it from going inside a directory, or
// a link to one, at "$p"; mv without it is for a developer's Mac.
const Replace = `if mv --version >/dev/null 2>&1; then mv -fT -- "$tmp" "$p"; else mv -f -- "$tmp" "$p"; fi`

// SyncFile and SyncDir flush "$tmp" and the directory holding "$p" to disk.
// GNU sync takes paths; where sync doesn't, everything is flushed instead.
const (
	SyncFile = `sync -- "$tmp" 2>/dev/null || sync`
	SyncDir  = `sync -- "$(dirname -- "$p")" 2>/dev/null || sync`
)

// Delete removes the file. Deleting a missing file succeeds.
func Delete(ctx context.Context, r modules.Runner, p string) error {
	_, err := run(ctx, r, modules.Guard("rm -f -- "+ssh.Quote(p), modules.Parent(p)), nil)
	return err
}

func run(ctx context.Context, r modules.Runner, script string, stdin []byte) (ssh.Result, error) {
	res, err := r.Run(ctx, script, stdin)
	if err != nil {
		return res, err
	}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(string(res.Stderr))
		if msg == "" {
			msg = fmt.Sprintf("exit status %d", res.ExitCode)
		}
		return res, errors.New(msg)
	}
	return res, nil
}
