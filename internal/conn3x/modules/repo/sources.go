// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package repo

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/modules/pkg"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// managed is the first line of every file a repository step writes, which
// marks it as Conn3x's for a package_sources step in any circuit.
const managed = "# Managed by Conn3x."

// DisabledDir is where a package_sources step moves the files it doesn't
// keep. Neither apt nor dnf reads anything there.
const DisabledDir = "/var/lib/conn3x/disabled-sources"

// Sources keeps a host to the distribution's package sources, Conn3x's,
// and Keep; Remove names a distribution file that goes anyway.
type Sources struct {
	Keep, Remove []string
}

// Validate checks the file names before anything reaches the host.
func (s Sources) Validate() error {
	for _, n := range append(append([]string{}, s.Keep...), s.Remove...) {
		if !repoName.MatchString(n) || n == "." || n == ".." {
			return fmt.Errorf("%q isn't a file name: letters, digits, ., - and _ only, such as \"docker.sources\"", n)
		}
	}
	for _, n := range s.Keep {
		if slices.Contains(s.Remove, n) {
			return fmt.Errorf("%s is in both keep and remove", n)
		}
	}
	return nil
}

// SourceFile is one file in the directory the package manager reads its
// added sources from.
type SourceFile struct {
	Name   string
	Marked bool     // its first line is a repository step's mark
	Owners []string // the packages that own it (dnf only)
}

// SourcesDir is where the family's package manager reads added sources.
// Fedora's own repositories are in /usr/share/dnf5/repos.d, which is the
// distribution's and isn't touched.
func SourcesDir(family pkg.Family) string {
	if family == pkg.RPM {
		return "/etc/yum.repos.d"
	}
	return "/etc/apt/sources.list.d"
}

// Unlisted returns the files that go, in order, given the host's os-release
// ID. A remove that names a marked file is an error: two steps would undo
// each other on every apply.
func (s Sources) Unlisted(family pkg.Family, id string, files []SourceFile) ([]string, error) {
	var gone []string
	for _, f := range files {
		removed := slices.Contains(s.Remove, f.Name)
		switch {
		case f.Marked && removed:
			return nil, fmt.Errorf("remove names %s, which a repository step wrote; delete that step instead", f.Name)
		case f.Marked, slices.Contains(s.Keep, f.Name):
		case removed || !distribution(family, id, f):
			gone = append(gone, f.Name)
		}
	}
	return gone, nil
}

func distribution(family pkg.Family, id string, f SourceFile) bool {
	if id == "" {
		return false
	}
	if family != pkg.RPM {
		return f.Name == id+".sources"
	}
	if id == "rhel" && f.Name == "redhat.repo" {
		return true // subscription-manager writes it
	}
	return slices.ContainsFunc(f.Owners, func(o string) bool { return strings.HasPrefix(o, id+"-repos") })
}

// listScript prints the os-release ID, then name, mark and owners for each
// file apt or dnf would read, NUL-separated. A symlink is never read for
// its mark, since it could point at a FIFO.
func listScript(family pkg.Family) string {
	glob, owners := "*.list *.sources", `o=`
	if family == pkg.RPM {
		glob, owners = "*.repo", `o=$(rpm -qf --qf '%{NAME} ' -- "$f" 2>/dev/null) || o=`
	}
	return fmt.Sprintf(`id=$(. /etc/os-release 2>/dev/null && printf %%s "$ID")
printf '%%s\0' "$id"
cd %s 2>/dev/null || exit 0
for f in %s; do
  [ -e "$f" ] || [ -L "$f" ] || continue
  m=0
  if [ -f "$f" ] && [ ! -L "$f" ]; then
    l=; IFS= read -r l < "$f" || :
    [ "$l" = %s ] && m=1
  fi
  %s
  printf '%%s\0%%s\0%%s\0' "$f" "$m" "$o"
done`, ssh.Quote(SourcesDir(family)), glob, ssh.Quote(managed), owners)
}

// ReadSources lists the host's added package sources and its os-release ID.
func ReadSources(ctx context.Context, r modules.Runner, family pkg.Family) (id string, files []SourceFile, err error) {
	res, err := r.Run(ctx, listScript(family), nil)
	if err != nil {
		return "", nil, err
	}
	if res.ExitCode != 0 {
		return "", nil, fmt.Errorf("listing %s: %s", SourcesDir(family), strings.TrimSpace(string(res.Stderr)))
	}
	return parseSources(string(res.Stdout))
}

func parseSources(out string) (string, []SourceFile, error) {
	fields := strings.Split(strings.TrimSuffix(out, "\x00"), "\x00")
	if len(fields)%3 != 1 {
		return "", nil, fmt.Errorf("unexpected listing of package sources: %q", out)
	}
	var files []SourceFile
	for i := 1; i+2 < len(fields); i += 3 {
		files = append(files, SourceFile{Name: fields[i], Marked: fields[i+1] == "1", Owners: strings.Fields(fields[i+2])})
	}
	return fields[0], files, nil
}

// Disable moves the named files into DisabledDir, keeping an older file of
// the same name as a numbered backup, then refreshes apt's package lists.
func Disable(ctx context.Context, h modules.Runner, family pkg.Family, names []string) error {
	if len(names) == 0 {
		return nil
	}
	quoted := make([]string, len(names))
	for i, n := range names {
		if n == "" || n == "." || n == ".." || strings.ContainsAny(n, "/\x00") {
			return fmt.Errorf("not moving %q: not a plain file name", n)
		}
		quoted[i] = ssh.Quote(SourcesDir(family) + "/" + n)
	}
	cmd := fmt.Sprintf("mkdir -p -m 0700 %[1]s && mv --backup=numbered -t %[1]s -- %[2]s", ssh.Quote(DisabledDir), strings.Join(quoted, " "))
	res, err := h.Run(ctx, cmd, nil)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("moving package sources to %s: %s", DisabledDir, strings.TrimSpace(string(res.Stderr)))
	}
	return refresh(ctx, h, family)
}
