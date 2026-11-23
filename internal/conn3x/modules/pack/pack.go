// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package pack packs files on a host into a tar or zip archive, and tells
// whether the files have changed since it was packed.
package pack

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

// Pack is an archive at Dest of Paths, with whatever matches Exclude left
// out. Paths are absolute; * and ? in a path's last part match names in its
// directory. Exclude patterns are matched against each entry's absolute
// path, with * and ? matching any characters, slashes too, and a match
// leaves out everything below it. Mode defaults to 0600.
type Pack struct {
	Paths, Exclude     []string
	Dest, Format       string
	Owner, Group, Mode string
}

// formats maps a format to tar's compression option and the program it
// runs. zip has no tar option; its program is zip itself.
var formats = map[string]struct{ flag, tool string }{
	"gz":   {" -z", "gzip"},
	"bz2":  {" -j", "bzip2"},
	"xz":   {" -J", "xz"},
	"zstd": {" --zstd", "zstd"},
	"tar":  {"", ""},
	"zip":  {"", "zip"},
}

var modeOctal = regexp.MustCompile(`^[0-7]{4}$`)

func (p Pack) format() string {
	if p.Format == "" {
		return "gz"
	}
	return p.Format
}

// Validate checks a Pack before anything reaches the host.
func (p Pack) Validate() error {
	if len(p.Paths) == 0 {
		return errors.New("set paths, the files and directories to pack")
	}
	for _, s := range p.Paths {
		if !path.IsAbs(s) || s != path.Clean(s) || s == "/" || strings.ContainsAny(s, "\r\n\x00") {
			return fmt.Errorf("path %q must be an absolute path below /, without a trailing slash or . and .. parts", s)
		}
		if strings.ContainsAny(path.Dir(s), "*?") {
			return fmt.Errorf("path %q has a wildcard before its last part; only the last part may have * or ?", s)
		}
	}
	if !path.IsAbs(p.Dest) || p.Dest != path.Clean(p.Dest) || p.Dest == "/" || strings.ContainsAny(p.Dest, "\r\n\x00") {
		return fmt.Errorf("dest %q must be an absolute path to a file", p.Dest)
	}
	for _, e := range p.Exclude {
		if !path.IsAbs(e) || strings.ContainsAny(e, "\r\n\x00") {
			return fmt.Errorf("exclude %q must be an absolute path or pattern", e)
		}
	}
	if _, ok := formats[p.format()]; !ok {
		return fmt.Errorf(`format %q must be one of "gz", "bz2", "xz", "zstd", "tar" or "zip"`, p.Format)
	}
	if p.Mode != "" && !modeOctal.MatchString(p.Mode) {
		return fmt.Errorf("mode %q must be four octal digits, like \"0640\"", p.Mode)
	}
	return nil
}

// Root is the directory names in the archive start from: the deepest one
// holding every path, as Ansible's archive module takes it. It ends in a
// slash.
func Root(paths []string) string {
	var common []string
	for i, p := range paths {
		parts := strings.Split(path.Dir(p), "/")
		if i == 0 {
			common = parts
			continue
		}
		n := 0
		for n < len(common) && n < len(parts) && common[n] == parts[n] {
			n++
		}
		common = common[:n]
	}
	r := strings.Join(common, "/")
	if !strings.HasSuffix(r, "/") {
		r += "/"
	}
	return r
}

// glob quotes s for the shell with * and ? left bare, so they match and
// nothing else in s means anything.
func glob(s string) string {
	var b strings.Builder
	for s != "" {
		i := strings.IndexAny(s, "*?")
		if i < 0 {
			i = len(s)
		}
		if i > 0 {
			b.WriteString(ssh.Quote(s[:i]))
		}
		if i < len(s) {
			b.WriteByte(s[i])
			i++
		}
		s = s[i:]
	}
	return b.String()
}

// list is shell that writes to "$list" every entry to pack, by its name in
// the archive, sorted, and leaves the script in Root. Dest is never listed,
// for an archive kept beside its sources. A directory find can't read is an
// error, not an archive that quietly leaves it out.
//
// shortcut: a name with a line break in it is read as two names, so tar
// fails on it; read the list NUL-separated if such names turn up.
func (p Pack) list() string {
	var b strings.Builder
	fmt.Fprintf(&b, "r=%s\ncd -- \"$r\"\nfor s in", ssh.Quote(Root(p.Paths)))
	for _, s := range p.Paths {
		b.WriteString(" " + glob(s))
	}
	b.WriteString(`; do [ -e "$s" ] || [ -h "$s" ] || continue; find "$s" 2>>"$errs"; done | while IFS= read -r f; do
  case "$f" in ` + ssh.Quote(p.Dest))
	for _, e := range p.Exclude {
		fmt.Fprintf(&b, " | %[1]s | %[1]s/*", glob(e))
	}
	b.WriteString(`) continue ;; esac
  printf '%s\n' "${f#"$r"}"
done | LC_ALL=C sort -u > "$list"
if [ -s "$errs" ]; then cat -- "$errs" >&2; exit 1; fi
`)
	return b.String()
}

// sum is shell that sets "$sum" to a SHA-256 over the type, mode, owner,
// group, size and modification time of every listed entry. A directory's
// size and time are left out: they change when anything is added to it,
// such as the archive itself, which the list already shows.
const sum = `sum=$(tr '\n' '\0' < "$list" | xargs -0r env LC_ALL=C stat -c '%F|%a|%u|%g|%s|%Y|%n' -- | sed 's/^\(directory|[^|]*|[^|]*|[^|]*|\)[^|]*|[^|]*|/\1||/' | sha256sum | cut -d' ' -f1)
`

const start = `set -e
list=$(mktemp)
errs=$(mktemp)
tmpd=
trap 'rm -f -- "$list" "$errs"; [ -z "$tmpd" ] || rm -rf -- "$tmpd"' EXIT
`

// routes are the paths a script reads through: the way to Root.
func (p Pack) routes() []modules.Route {
	r := Root(p.Paths)
	if r != "/" {
		r = strings.TrimSuffix(r, "/")
	}
	return []modules.Route{modules.Follow(r), modules.Follow(p.Dest)}
}

// Read returns the SHA-256 over the entries Apply would pack now, and
// whether Dest is there.
func Read(ctx context.Context, r modules.Runner, p Pack) (string, bool, error) {
	if err := p.Validate(); err != nil {
		return "", false, err
	}
	d := ssh.Quote(p.Dest)
	script := modules.Settled + start + p.list() + sum + `printf '%s\n' "$sum"
if route_settled ` + d + ` && [ -f ` + d + ` ]; then echo present; else echo absent; fi`
	res, err := r.Run(ctx, modules.Guard(script, p.routes()...), nil)
	if err := check(res, err); err != nil {
		return "", false, err
	}
	out := strings.Fields(string(res.Stdout))
	if len(out) != 2 {
		return "", false, fmt.Errorf("reading what %s is packed from printed %q", p.Dest, res.Stdout)
	}
	return out[0], out[1] == "present", nil
}

// command is the shell that checks the tools are there and packs the list
// into "$tmp", from Root.
func (p Pack) command() string {
	f := formats[p.format()]
	var b strings.Builder
	if p.format() == "zip" {
		b.WriteString(missing("zip", "zip"))
		// -nw: names in the list are names, never patterns. zip adds .zip to a
		// name without one, so "$tmp" has it.
		b.WriteString(`zip -q -y -nw "$tmp" -@ < "$list"` + "\n")
		return b.String()
	}
	b.WriteString(`tar --version 2>/dev/null | grep -q GNU || { echo "GNU tar isn't on this host: install the tar package, for example with a package step before this one" >&2; exit 1; }` + "\n")
	if f.tool != "" {
		b.WriteString(missing(f.tool, p.format()))
	}
	fmt.Fprintf(&b, "tar -c -f \"$tmp\"%s --no-recursion --verbatim-files-from -T \"$list\"\n", f.flag)
	return b.String()
}

func missing(tool, format string) string {
	return fmt.Sprintf("command -v %[1]s >/dev/null 2>&1 || { echo \"%[1]s isn't on this host, and format %[2]s needs it: install it, for example with a package step before this one\" >&2; exit 1; }\n", tool, format)
}

// Apply packs the entries into a new archive beside Dest and moves it into
// place, so Dest is never half written. It returns the SHA-256 Read gives
// for what it packed. Ansible's module requires Dest's directory to be
// there, and so does this.
func Apply(ctx context.Context, r modules.Runner, p Pack) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	mode := p.Mode
	if mode == "" {
		mode = "0600"
	}
	var b strings.Builder
	b.WriteString(start + "p=" + ssh.Quote(p.Dest) + "\n")
	for _, s := range p.Paths {
		if !strings.ContainsAny(s, "*?") {
			fmt.Fprintf(&b, "[ -e %[1]s ] || [ -h %[1]s ] || { echo %[2]s >&2; exit 1; }\n", ssh.Quote(s), ssh.Quote(s+" doesn't exist, so it can't be packed"))
		}
	}
	b.WriteString(p.list())
	b.WriteString(`[ -s "$list" ] || { echo "nothing matches paths, so there is nothing to pack" >&2; exit 1; }
` + sum + `tmpd=$(mktemp -d "$(dirname -- "$p")/.conn3x.XXXXXX")
tmp=$tmpd/new.zip
` + p.command() + `chmod ` + mode + ` "$tmp"
` + file.Ownership(p.Owner, p.Group) + file.SyncFile + "\n" + file.Replace + "\n" + file.SyncDir + `
if command -v restorecon >/dev/null 2>&1; then restorecon -- "$p" 2>/dev/null || true; fi
printf '%s\n' "$sum"`)
	routes := append([]modules.Route{modules.Parent(p.Dest)}, p.routes()[0])
	res, err := r.Run(ctx, modules.GuardWrite(b.String(), modules.Write{Owner: p.Owner, Group: p.Group, Path: p.Dest}, routes...), nil)
	if err := check(res, err); err != nil {
		return "", err
	}
	out := strings.Fields(string(res.Stdout))
	if len(out) == 0 {
		return "", fmt.Errorf("packing %s printed nothing", p.Dest)
	}
	return out[len(out)-1], nil
}

// Delete removes the archive.
func Delete(ctx context.Context, r modules.Runner, dest string) error {
	return file.Delete(ctx, r, dest)
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
