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
	Deb: `dpkg --print-architecture && dpkg-query -W -f '${db:Status-Abbrev}\t${Package}\t${Architecture}\t${Version}\n' | awk -F '\t' 'substr($1, 2, 1) == "i" { print $2 "\t" $3 "\t" $4 }'`,
	RPM: `uname -m && rpm -qa --qf '%{NAME}\t%{ARCH}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n'`,
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
