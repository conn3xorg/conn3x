// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package pkg

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
)

// inventoryCmd prints the host's architecture, then name, architecture and
// version for each installed package, tab-separated, in the form Read
// gives versions in. dpkg lists only what's installed, held or not.
var inventoryCmd = map[Family]string{
	Deb:  `dpkg --print-architecture && dpkg-query -W -f '${db:Status-Abbrev}\t${Package}\t${Architecture}\t${Version}\n' | awk -F '\t' 'substr($1, 2, 1) == "i" { print $2 "\t" $3 "\t" $4 }'`,
	RPM:  `uname -m && rpm -qa --qf '%{NAME}\t%{ARCH}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n'`,
	SUSE: `uname -m && rpm -qa --qf '%{NAME}\t%{ARCH}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n'`,
	// apk list -I prints "name-version-rN arch {origin} (license) [installed]";
	// the name is what comes before the last two dashes.
	APK: `apk --print-arch && apk list -I | awk '{ n = $1; sub(/-[^-]+-r[0-9]+$/, "", n); print n "\t" $2 "\t" substr($1, length(n) + 2) }'`,
}

// Inventory returns every installed package's versions, oldest first, by
// name. A package of the host's own architecture, or of none, goes under
// its bare name. Another architecture's goes under the name its own tools
// print: libc6:i386 for dpkg, glibc.i686 for rpm.
func Inventory(ctx context.Context, r modules.Runner, family Family) (map[string][]string, error) {
	cmd, ok := inventoryCmd[family]
	if !ok {
		return nil, fmt.Errorf("unknown package family %q", family)
	}
	res, err := r.Run(ctx, cmd, nil)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("listing installed packages: %s", strings.TrimSpace(string(res.Stderr)))
	}
	return parseInventory(family, string(res.Stdout))
}

func parseInventory(family Family, out string) (map[string][]string, error) {
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	native := strings.TrimSpace(lines[0])
	got := map[string][]string{}
	for _, l := range lines[1:] {
		f := strings.Split(l, "\t")
		if len(f) != 3 || f[0] == "" {
			return nil, fmt.Errorf("listing installed packages: unexpected line %q", l)
		}
		name, arch, version := f[0], f[1], f[2]
		if arch != native && arch != "all" && arch != "noarch" && arch != "(none)" && arch != "" {
			if family == Deb {
				name += ":" + arch
			} else {
				name += "." + arch
			}
		}
		got[name] = append(got[name], version)
	}
	for _, vs := range got {
		// dpkg installs one version of a name per architecture, so only
		// rpm can have several, such as installonly kernels.
		sort.SliceStable(vs, func(i, j int) bool { return rpmCompare(vs[i], vs[j]) < 0 })
	}
	return got, nil
}

// rpmCompare orders two epoch:version-release strings as rpm does: epoch,
// then version, then release, each with rpmvercmp.
func rpmCompare(a, b string) int {
	ea, va, ra := splitEVR(a)
	eb, vb, rb := splitEVR(b)
	if c := rpmvercmp(ea, eb); c != 0 {
		return c
	}
	if c := rpmvercmp(va, vb); c != 0 {
		return c
	}
	return rpmvercmp(ra, rb)
}

func splitEVR(s string) (epoch, version, release string) {
	epoch = "0"
	if e, rest, ok := strings.Cut(s, ":"); ok {
		epoch, s = e, rest
	}
	if i := strings.LastIndex(s, "-"); i >= 0 {
		return epoch, s[:i], s[i+1:]
	}
	return epoch, s, ""
}

// rpmvercmp is rpm's version comparison: segments of digits or of letters,
// compared numerically or as strings, with ~ sorting before anything, even
// the end, and ^ after the end but before anything else.
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	isAlnum := func(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
	isDigit := func(c byte) bool { return c >= '0' && c <= '9' }
	for len(a) > 0 || len(b) > 0 {
		for len(a) > 0 && !isAlnum(a[0]) && a[0] != '~' && a[0] != '^' {
			a = a[1:]
		}
		for len(b) > 0 && !isAlnum(b[0]) && b[0] != '~' && b[0] != '^' {
			b = b[1:]
		}
		if len(a) > 0 && a[0] == '~' || len(b) > 0 && b[0] == '~' {
			if len(a) == 0 || a[0] != '~' {
				return 1
			}
			if len(b) == 0 || b[0] != '~' {
				return -1
			}
			a, b = a[1:], b[1:]
			continue
		}
		if len(a) > 0 && a[0] == '^' || len(b) > 0 && b[0] == '^' {
			if len(a) == 0 {
				return -1
			}
			if len(b) == 0 {
				return 1
			}
			if a[0] != '^' {
				return 1
			}
			if b[0] != '^' {
				return -1
			}
			a, b = a[1:], b[1:]
			continue
		}
		if len(a) == 0 || len(b) == 0 {
			break
		}
		digits := isDigit(a[0])
		take := func(s string) (string, string) {
			i := 0
			for i < len(s) && (digits && isDigit(s[i]) || !digits && isAlnum(s[i]) && !isDigit(s[i])) {
				i++
			}
			return s[:i], s[i:]
		}
		var sa, sb string
		sa, a = take(a)
		sb, b = take(b)
		if sb == "" {
			// A number is newer than letters.
			if digits {
				return 1
			}
			return -1
		}
		if digits {
			sa, sb = strings.TrimLeft(sa, "0"), strings.TrimLeft(sb, "0")
			if len(sa) != len(sb) {
				if len(sa) > len(sb) {
					return 1
				}
				return -1
			}
		}
		if c := strings.Compare(sa, sb); c != 0 {
			return c
		}
	}
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return -1
	default:
		return 1
	}
}

// manualCmd prints the names of the packages someone asked for, as opposed
// to those pulled in as dependencies or shipped with the image. dnf's
// user-installed list says it (dnf 4 and 5 both take --qf; dnf 4 adds its
// own newline, so blank lines are skipped). apt's manual marks don't on
// their own, since images built with debootstrap mark nearly everything
// manual, so Deb also prints each package's essential flag, priority and
// what it needs, after a line of @@@, for debManual to filter.
var manualCmd = map[Family]string{
	Deb: `apt-mark showmanual && echo @@@ && dpkg-query -W -f '${db:Status-Abbrev}\t${Package}\t${Essential}\t${Priority}\t${Depends}, ${Pre-Depends}, ${Recommends}\n'`,
	RPM: `command -v dnf >/dev/null || { echo "listing hand-installed packages needs dnf" >&2; exit 1; }; dnf -q repoquery --userinstalled --qf '%{name}\n'`,
	// zypper records what it installed as a dependency, so the rest of
	// what rpm has was asked for, by hand or by the image.
	SUSE: `rpm -qa --qf '%{NAME}\n' | sort -u | { if [ -s /var/lib/zypp/AutoInstalled ]; then grep -vxF -f /var/lib/zypp/AutoInstalled; else cat; fi; }`,
	// /etc/apk/world is what was asked for, each perhaps with a version
	// constraint such as nginx=1.26.2-r0 or a repository tag such as
	// nginx@edge.
	APK: `sed -e 's/[=<>~@].*//' /etc/apk/world`,
}

// Manual returns the names of the packages installed by hand, as the tool
// prints them: apt's with :arch for another architecture, as Inventory's
// are, and dnf's bare, so match those with BareName.
func Manual(ctx context.Context, r modules.Runner, family Family) (map[string]bool, error) {
	cmd, ok := manualCmd[family]
	if !ok {
		return nil, fmt.Errorf("unknown package family %q", family)
	}
	res, err := r.Run(ctx, cmd, nil)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("listing hand-installed packages: %s", strings.TrimSpace(string(res.Stderr)))
	}
	if family == Deb {
		return debManual(string(res.Stdout))
	}
	got := map[string]bool{}
	for _, l := range strings.Split(string(res.Stdout), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			got[l] = true
		}
	}
	return got, nil
}

// debManual keeps the packages apt marks manual that no other installed
// package depends on, pre-depends on or recommends, and that aren't
// essential, required or important: what someone installed, not the base
// system an image marked manual wholesale. A package another needs is
// adopted with the one that needs it.
func debManual(out string) (map[string]bool, error) {
	marks, packages, ok := strings.Cut(out, "@@@\n")
	if !ok {
		return nil, fmt.Errorf("listing hand-installed packages: unexpected output")
	}
	needed, base := map[string]bool{}, map[string]bool{}
	for _, l := range strings.Split(packages, "\n") {
		f := strings.Split(l, "\t")
		if len(f) != 5 || len(f[0]) < 2 || f[0][1] != 'i' {
			continue
		}
		if f[2] == "yes" || f[3] == "required" || f[3] == "important" {
			base[f[1]] = true
		}
		for _, alt := range strings.Split(f[4], ",") {
			for _, d := range strings.Split(alt, "|") {
				d, _, _ = strings.Cut(strings.TrimSpace(d), " ")
				needed[strings.TrimSuffix(d, ":any")] = true
			}
		}
	}
	got := map[string]bool{}
	for _, p := range strings.Fields(marks) {
		if bare, _, _ := strings.Cut(p, ":"); !needed[p] && !needed[bare] && !base[bare] {
			got[p] = true
		}
	}
	return got, nil
}

// BareName is an rpm Inventory name without the architecture another
// architecture's package carries: glibc for glibc.i686.
func BareName(name string) string {
	for _, arch := range []string{".i686", ".i386", ".x86_64", ".aarch64", ".noarch", ".ppc64le", ".s390x", ".armv7hl"} {
		if strings.HasSuffix(name, arch) {
			return strings.TrimSuffix(name, arch)
		}
	}
	return name
}
