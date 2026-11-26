// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package pkg

import (
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// sourcePattern is an absolute path to a .deb or .rpm with nothing a shell
// would read in it, quoted or not.
var sourcePattern = regexp.MustCompile(`^/[A-Za-z0-9._+~@%=,:/-]*\.(deb|rpm)$`)

var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (d Desired) validateSource() error {
	if d.SourceSHA256 != "" {
		if d.Source == "" {
			return errors.New("source_sha256 only applies with source")
		}
		if !sha256Pattern.MatchString(d.SourceSHA256) {
			return fmt.Errorf("source_sha256 %q must be 64 lowercase hex characters", d.SourceSHA256)
		}
	}
	if d.Source == "" {
		return nil
	}
	if !sourcePattern.MatchString(d.Source) || path.Clean(d.Source) != d.Source {
		return fmt.Errorf("source %q must be an absolute path to a .deb or .rpm file, of letters, digits and . _ + ~ @ %% = , : - / only", d.Source)
	}
	if d.Version != "" {
		return errors.New("version can't be set with source: the file says which version it is")
	}
	if d.State == Latest {
		return errors.New("state \"latest\" can't be set with source: the file says which version it is")
	}
	return nil
}

// sourceFits says why family can't install the file at src, if it can't.
func sourceFits(family Family, src string) error {
	switch {
	case family == APK:
		return errors.New("source doesn't apply on Alpine: apk installs from its repositories here")
	case strings.HasSuffix(src, ".deb") && family != Deb:
		return fmt.Errorf("source %s is a .deb, and this host installs .rpm packages", src)
	case strings.HasSuffix(src, ".rpm") && family == Deb:
		return fmt.Errorf("source %s is an .rpm, and this host installs .deb packages", src)
	}
	return nil
}

// ReadSource reads the package name and version from the file at src:
// epoch:version-release for an .rpm, as Read gives an installed one, and
// the Version field for a .deb, as dpkg-query gives it. Both are "" when
// the file is missing, which isn't an error: an earlier step, such as a
// download, may not have run yet.
func ReadSource(ctx context.Context, r modules.Runner, family Family, src string) (name, version string, err error) {
	if err := (Desired{Name: "x", State: Present, Source: src}).validateSource(); err != nil {
		return "", "", err
	}
	if err := sourceFits(family, src); err != nil {
		return "", "", err
	}
	query := `rpm -qp --qf '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}\n' -- "$f"`
	if family == Deb {
		query = `dpkg-deb -f "$f" Package Version`
	}
	script := modules.Settled + fmt.Sprintf(`f=%s
if route_settled "$f" && [ -e "$f" ]; then
  [ -f "$f" ] || { echo "source $f is not a regular file" >&2; exit 1; }
  %s
else echo missing; fi`, ssh.Quote(src), query)
	res, err := r.Run(ctx, modules.Guard(script, modules.Follow(src)), nil)
	if err != nil {
		return "", "", err
	}
	if res.ExitCode != 0 {
		return "", "", fmt.Errorf("reading %s: %s (exit status %d)", src, strings.TrimSpace(string(res.Stderr)), res.ExitCode)
	}
	out := strings.TrimSpace(string(res.Stdout))
	if out == "missing" {
		return "", "", nil
	}
	if family == Deb {
		for _, line := range strings.Split(out, "\n") {
			k, v, _ := strings.Cut(line, ":")
			switch strings.TrimSpace(k) {
			case "Package":
				name = strings.TrimSpace(v)
			case "Version":
				version = strings.TrimSpace(v)
			}
		}
	} else if f := strings.Fields(out); len(f) == 2 {
		name, version = f[0], f[1]
	}
	if !namePattern.MatchString(name) || !versionPattern.MatchString(version) {
		return "", "", fmt.Errorf("reading %s: unexpected output %q", src, out)
	}
	return name, version, nil
}

// SourceSum reads the SHA-256 of the file at src, or "" when it's missing.
func SourceSum(ctx context.Context, r modules.Runner, src string) (string, error) {
	if err := (Desired{Name: "x", State: Present, Source: src}).validateSource(); err != nil {
		return "", err
	}
	script := modules.Settled + modules.Sum256 + fmt.Sprintf(`f=%s
if route_settled "$f" && [ -f "$f" ]; then sum256 "$f"; fi`, ssh.Quote(src))
	res, err := r.Run(ctx, modules.Guard(script, modules.Follow(src)), nil)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("hashing %s: %s (exit status %d)", src, strings.TrimSpace(string(res.Stderr)), res.ExitCode)
	}
	sum := strings.TrimSpace(string(res.Stdout))
	if sum != "" && !sha256Pattern.MatchString(sum) {
		return "", fmt.Errorf("hashing %s: unexpected output %q", src, sum)
	}
	return sum, nil
}

// applySource installs the package from the file at d.Source, after
// checking that the file is that package. apt-get and dnf resolve its
// dependencies from the repositories, d's included, which dpkg -i and
// rpm -U don't.
func applySource(ctx context.Context, r modules.Runner, family Family, d Desired) error {
	name, version, err := ReadSource(ctx, r, family, d.Source)
	if err != nil {
		return err
	}
	if version == "" {
		return fmt.Errorf("source %s doesn't exist on the host; a step that creates it, such as a download, has to come first", d.Source)
	}
	if name != d.Name {
		return fmt.Errorf("source %s is the package %s, not %s", d.Source, name, d.Name)
	}
	q := ssh.Quote(d.Source)
	var cmd string
	switch family {
	case Deb:
		cmd = aptGet + d.recommends(family) + d.repoOptions(family) + " --allow-downgrades install " + q
	case RPM:
		// dnf install refuses a version older than the one installed.
		verb := "install"
		if a, err := Read(ctx, r, family, d.Name, false); err == nil && a.Installed && rpmCompare(version, a.Version) < 0 {
			verb = "downgrade"
		}
		cmd = "dnf -y" + d.recommends(family) + d.repoOptions(family) + " " + verb + " " + q
	case SUSE:
		// zypper -n refuses an unsigned file, which dnf and apt install
		// from a path. --no-gpg-checks would skip the repositories' too.
		cmd = zypperCommand("install --oldpackage --allow-unsigned-rpm" + d.recommends(family) + " " + q)
	}
	if d.SourceSHA256 != "" {
		// Checked in the same guarded script as the install, where only
		// root can change the file, so the install gets the file checked.
		cmd = modules.Sum256 + fmt.Sprintf(`got=$([ -f %[1]s ] && sum256 %[1]s)
[ "$got" = %[2]s ] || { echo "source %[3]s has SHA-256 ${got:-unreadable}, not source_sha256 %[2]s; refusing to install it" >&2; exit 1; }
`, q, d.SourceSHA256, d.Source) + cmd
	}
	// What the file holds runs as root, so Whole refuses a file, or a
	// directory on the way, that anyone but root could change.
	cmd = modules.GuardRoot(cmd, modules.Whole(d.Source))
	err = Run(ctx, r, cmd)
	if err != nil && family == Deb && staleLists(err) {
		if err := UpdateLists(ctx, r); err != nil {
			return err
		}
		err = Run(ctx, r, cmd)
	}
	return err
}
