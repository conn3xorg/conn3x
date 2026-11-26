// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package pkg installs, upgrades and removes OS packages with dnf on the
// Red Hat family, zypper on SUSE, apt on Debian and Ubuntu, and apk on
// Alpine.
package pkg

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"regexp"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Family is a package manager family.
type Family string

const (
	RPM Family = "rpm"
	Deb Family = "deb"
	APK Family = "apk"
	// SUSE is RPM underneath, with zypper rather than dnf.
	SUSE Family = "suse"
)

// State is what should be true of the package.
type State string

const (
	Present State = "present"
	Absent  State = "absent"
	Latest  State = "latest"
)

// Desired describes the package as it should be.
type Desired struct {
	Name    string
	State   State
	Version string // optional, with Present
	// Source, when set, is a .deb or .rpm file on the host to install
	// the package from. Name stays the package's name.
	Source string
	// InstallRecommends, when set, says whether an install also brings in
	// what the package recommends: apt's recommended packages, dnf's weak
	// dependencies. Nil keeps the host's own setting.
	InstallRecommends *bool
	// EnableRepositories are dnf repository IDs, such as crb, to turn on
	// for the install and the newest-version query only, as dnf's
	// --enablerepo does. Red Hat family only.
	EnableRepositories []string
	// TargetRelease is an apt release, such as trixie-backports, to
	// install from and read the candidate from, as apt's -t does. Debian
	// family only.
	TargetRelease string
}

// repoOptions is the option that sets EnableRepositories or TargetRelease
// for a family's install or query, or "". Validate has checked each value.
func (d Desired) repoOptions(family Family) string {
	var b strings.Builder
	switch family {
	case RPM:
		for _, id := range d.EnableRepositories {
			b.WriteString(" --enablerepo=" + ssh.Quote(id))
		}
	case Deb:
		if d.TargetRelease != "" {
			b.WriteString(" -t " + ssh.Quote(d.TargetRelease))
		}
	}
	return b.String()
}

// Fits says why family can't take what d sets, if it can't. dnf has
// --enablerepo and apt has -t; zypper and apk have neither as such.
func (d Desired) Fits(family Family) error {
	if len(d.EnableRepositories) > 0 && family != RPM {
		return fmt.Errorf("enable_repositories only applies on the Red Hat family, with dnf, and this host uses %s", familyTool[family])
	}
	if d.TargetRelease != "" && family != Deb {
		return fmt.Errorf("target_release only applies on Debian and Ubuntu, with apt, and this host uses %s", familyTool[family])
	}
	return nil
}

var familyTool = map[Family]string{RPM: "dnf", Deb: "apt", SUSE: "zypper", APK: "apk"}

// recommends is the option that sets InstallRecommends for a family, or ""
// to keep the host's setting.
func (d Desired) recommends(family Family) string {
	if d.InstallRecommends == nil {
		return ""
	}
	if family == RPM {
		return map[bool]string{true: " --setopt=install_weak_deps=True", false: " --setopt=install_weak_deps=False"}[*d.InstallRecommends]
	}
	if family == SUSE {
		return map[bool]string{true: " --recommends", false: " --no-recommends"}[*d.InstallRecommends]
	}
	return map[bool]string{true: " -o APT::Install-Recommends=yes", false: " -o APT::Install-Recommends=no"}[*d.InstallRecommends]
}

// Actual describes the package as it is.
type Actual struct {
	Installed bool
	Version   string // as the package manager reports it
	Candidate string // newest available, only read for Latest
	// SourceVersion is the version of the file at Desired.Source, as
	// ReadSource read it, or "" when it was missing or not read.
	SourceVersion string
}

var (
	// A name never ends in "-": no package does, and apt reads "install x-"
	// as "remove x". It may end in "+", as g++ does; see exactDeb.
	namePattern    = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.+_:@-]*[A-Za-z0-9+])?$`)
	versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+~:_-]*$`)
	// dnf allows letters, digits and - _ . : in a repository ID. Globs,
	// which --enablerepo also takes, aren't allowed here.
	repoIDPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.:-]*$`)
	// An apt release is a suite, codename or version, such as
	// trixie-backports, stable or 13.
	releasePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+~_-]*$`)
)

// ValidName reports whether name passes the check Validate applies. A
// converter uses it to leave a name that could never validate for review.
func ValidName(name string) bool { return namePattern.MatchString(name) }

// Validate checks a Desired before anything runs on a host.
func (d Desired) Validate() error {
	if !namePattern.MatchString(d.Name) {
		return fmt.Errorf("package name %q is not valid", d.Name)
	}
	switch d.State {
	case Present, Latest:
	case Absent:
		if d.Version != "" {
			return errors.New("version only applies when state is \"present\"")
		}
	default:
		return fmt.Errorf("state must be %q, %q or %q, not %q", Present, Absent, Latest, d.State)
	}
	if err := d.validateSource(); err != nil {
		return err
	}
	for _, id := range d.EnableRepositories {
		if !repoIDPattern.MatchString(id) {
			return fmt.Errorf("repository ID %q is not valid: use letters, digits and - _ . : only", id)
		}
	}
	if d.TargetRelease != "" && !releasePattern.MatchString(d.TargetRelease) {
		return fmt.Errorf("target_release %q is not valid: use a suite or codename such as trixie-backports, of letters, digits and . + ~ _ - only", d.TargetRelease)
	}
	if len(d.EnableRepositories) > 0 && d.TargetRelease != "" {
		return errors.New("enable_repositories is for dnf and target_release for apt, so a step sets one or the other")
	}
	if d.Version != "" {
		if d.State == Latest {
			return errors.New("version only applies when state is \"present\"")
		}
		if !versionPattern.MatchString(d.Version) {
			return fmt.Errorf("version %q is not valid", d.Version)
		}
	}
	return nil
}

// DetectFamily reads /etc/os-release to choose the package manager.
func DetectFamily(ctx context.Context, r modules.Runner) (Family, error) {
	res, err := r.Run(ctx, "cat /etc/os-release", nil)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("reading /etc/os-release: %s", strings.TrimSpace(string(res.Stderr)))
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			fields[k] = strings.Trim(v, `"'`)
		}
	}
	ids := append([]string{fields["ID"]}, strings.Fields(fields["ID_LIKE"])...)
	for _, id := range ids {
		switch id {
		case "rhel", "fedora", "centos", "rocky", "almalinux":
			return RPM, nil
		case "debian", "ubuntu":
			return Deb, nil
		case "alpine":
			return APK, nil
		case "suse", "opensuse", "sles", "sled", "opensuse-leap", "opensuse-tumbleweed":
			return SUSE, nil
		}
	}
	return "", fmt.Errorf("%s is not supported yet; Conn3x manages packages on the Red Hat family, SUSE, Debian and Ubuntu, and Alpine", fields["ID"])
}

// Read reports whether the package is installed. With candidate set it also
// asks the package manager for the newest available version.
func Read(ctx context.Context, r modules.Runner, family Family, name string, candidate bool) (Actual, error) {
	return read(ctx, r, family, name, candidate, "")
}

// ReadFor is Read for d: the newest version, read for Latest, is the one
// d's repositories or release offer.
func ReadFor(ctx context.Context, r modules.Runner, family Family, d Desired) (Actual, error) {
	if err := d.Fits(family); err != nil {
		return Actual{}, err
	}
	return read(ctx, r, family, d.Name, d.State == Latest, d.repoOptions(family))
}

func read(ctx context.Context, r modules.Runner, family Family, name string, candidate bool, opts string) (Actual, error) {
	if !namePattern.MatchString(name) {
		return Actual{}, fmt.Errorf("package name %q is not valid", name)
	}
	q := ssh.Quote(name)
	var a Actual
	switch family {
	case RPM, SUSE:
		const qf = "--qf '%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n' -- "
		res, err := r.Run(ctx, "rpm -q "+qf+q, nil)
		if err == nil && res.ExitCode != 0 {
			// The name may be one another package provides, as wget is on
			// Fedora, where dnf installs wget2-wget for it.
			res, err = r.Run(ctx, "rpm -q --whatprovides "+qf+q, nil)
		}
		if err != nil {
			return a, err
		}
		if res.ExitCode == 0 {
			lines := strings.Fields(string(res.Stdout))
			if len(lines) > 0 {
				last := lines[len(lines)-1]
				if i := strings.LastIndex(last, "."); i > 0 {
					last = last[:i]
				}
				a = Actual{Installed: true, Version: last}
			}
		}
		if candidate && family == SUSE {
			res, err := r.Run(ctx, "zypper -n -q refresh >/dev/null 2>&1; zypper -n -q -x search -s --match-exact -t package "+q, nil)
			if err != nil {
				return a, err
			}
			a.Candidate = zypperNewest(string(res.Stdout), name)
		} else if candidate {
			res, err := r.Run(ctx, "dnf -q"+opts+" repoquery --latest-limit 1 --qf '%{epoch}:%{version}-%{release}' -- "+q, nil)
			if err != nil {
				return a, err
			}
			if res.ExitCode != 0 {
				return a, fmt.Errorf("finding the newest %s: %s", name, strings.TrimSpace(string(res.Stderr)))
			}
			a.Candidate = strings.TrimSpace(string(res.Stdout))
		}
	case Deb:
		res, err := r.Run(ctx, "dpkg-query -W -f '${db:Status-Abbrev} ${Version}\\n' -- "+q, nil)
		if err != nil {
			return a, err
		}
		if res.ExitCode == 0 {
			fields := strings.Fields(string(res.Stdout))
			// The second letter is the status: "ii" is installed, and so is
			// "hi", a package held with apt-mark hold.
			if len(fields) >= 2 && len(fields[0]) >= 2 && fields[0][1] == 'i' {
				a = Actual{Installed: true, Version: fields[1]}
			}
		}
		if candidate {
			res, err := r.Run(ctx, "apt-cache"+opts+" policy -- "+q, nil)
			if err != nil {
				return a, err
			}
			for _, line := range strings.Split(string(res.Stdout), "\n") {
				if v, ok := strings.CutPrefix(strings.TrimSpace(line), "Candidate:"); ok {
					if v = strings.TrimSpace(v); v != "(none)" {
						a.Candidate = v
					}
				}
			}
		}
	case APK:
		res, err := r.Run(ctx, "apk list -I "+q, nil)
		if err != nil {
			return a, err
		}
		if v := apkVersion(string(res.Stdout), name); v != "" {
			a = Actual{Installed: true, Version: v}
		}
		if candidate {
			// apk list reads the index, which a fresh host hasn't fetched.
			res, err := r.Run(ctx, "apk update -q >/dev/null 2>&1; apk list "+q, nil)
			if err != nil {
				return a, err
			}
			a.Candidate = apkVersion(string(res.Stdout), name)
		}
	default:
		return a, fmt.Errorf("unknown package family %q", family)
	}
	return a, nil
}

// zypperEdition is one solvable in zypper -x search's output.
var zypperEdition = regexp.MustCompile(`<solvable [^>]*name="([^"]+)"[^>]*edition="([^"]+)"`)

// zypperNewest is the newest edition of name that zypper -x search lists,
// one per repository, as epoch:version-release, the form rpm -q gives, or
// "".
func zypperNewest(out, name string) string {
	newest := ""
	for _, m := range zypperEdition.FindAllStringSubmatch(out, -1) {
		if m[1] != name {
			continue
		}
		e := m[2]
		if !strings.Contains(e, ":") {
			e = "0:" + e
		}
		if newest == "" || rpmCompare(e, newest) > 0 {
			newest = e
		}
	}
	return newest
}

// apkVersion is name's version in apk list's output, whose lines start
// "name-version-rN arch", or "". A line for another package whose name
// starts the same, such as tree-doc for tree, isn't name's: what follows
// the name and its dash must start with a digit.
func apkVersion(out, name string) string {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if v, ok := strings.CutPrefix(f[0], name+"-"); ok && v != "" && v[0] >= '0' && v[0] <= '9' {
			return v
		}
	}
	return ""
}

// NeedsChange reports whether Apply would change anything.
func NeedsChange(d Desired, a Actual) bool {
	switch d.State {
	case Absent:
		return a.Installed
	case Latest:
		return !a.Installed || (a.Candidate != "" && a.Candidate != a.Version)
	default:
		return !a.Installed || (d.Version != "" && !versionMatches(a.Version, d.Version)) ||
			(d.Source != "" && a.SourceVersion != "" && a.SourceVersion != a.Version)
	}
}

// Settled reports whether the host already has the package as d wants it,
// so Apply has nothing to do. A package that's absent and should stay so
// is the common case: running apt-get remove for it anyway queues behind
// every other package step and behind apt's lock, which a host that just
// booted holds for minutes while unattended-upgrades runs.
func Settled(ctx context.Context, r modules.Runner, family Family, d Desired) bool {
	a, err := ReadFor(ctx, r, family, d)
	if err == nil && d.Source != "" && d.State != Absent {
		// A file that's gone, as from /tmp after a reboot, leaves an
		// installed package as it is, as the plan does. Without the
		// package, Apply says the file is missing.
		if _, a.SourceVersion, err = ReadSource(ctx, r, family, d.Source); err == nil && a.SourceVersion == "" {
			return a.Installed
		}
	}
	return err == nil && !NeedsChange(d, a)
}

// versionMatches accepts an exact match, or want as the leading part of a
// full version: "1.26.3" matches "1:1.26.3-2.el10".
func versionMatches(actual, want string) bool {
	if !strings.Contains(want, ":") {
		if _, rest, ok := strings.Cut(actual, ":"); ok {
			actual = rest
		}
	}
	return actual == want || strings.HasPrefix(actual, want+"-")
}

const aptGet = "DEBIAN_FRONTEND=noninteractive apt-get -y -q -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"

// Apply installs, upgrades or removes the package.
func Apply(ctx context.Context, r modules.Runner, family Family, d Desired) error {
	if err := d.Validate(); err != nil {
		return err
	}
	if err := d.Fits(family); err != nil {
		return err
	}
	if d.Source != "" && d.State != Absent {
		return applySource(ctx, r, family, d)
	}
	switch family {
	case RPM:
		spec := d.Name
		if d.Version != "" {
			spec += "-" + d.Version
		}
		switch d.State {
		case Absent:
			return Run(ctx, r, "dnf -y remove "+ssh.Quote(d.Name))
		case Latest:
			if err := Run(ctx, r, "dnf -y"+d.recommends(family)+d.repoOptions(family)+" install "+ssh.Quote(d.Name)); err != nil {
				return err
			}
			return Run(ctx, r, "dnf -y"+d.recommends(family)+d.repoOptions(family)+" upgrade "+ssh.Quote(d.Name))
		default:
			return Run(ctx, r, "dnf -y"+d.recommends(family)+d.repoOptions(family)+" install "+ssh.Quote(spec))
		}
	case Deb:
		spec := d.Name
		if d.Version != "" {
			spec += "=" + d.Version
		}
		if d.State == Absent {
			return Run(ctx, r, exactDeb(d.Name, `dpkg-query -W -f '${Package}\n' --`)+aptGet+" remove "+ssh.Quote(d.Name))
		}
		install := exactDeb(d.Name, "apt-cache pkgnames --") + aptGet + d.recommends(family) + d.repoOptions(family) + " install " + ssh.Quote(spec)
		err := Run(ctx, r, install)
		if err != nil && staleLists(err) {
			// Fresh hosts often have no package lists yet, and an image a few
			// weeks old has lists naming versions the mirror has since dropped.
			// A first-boot apt-get update can also replace the lists while this
			// install runs. Taking the lists lock here waits that one out too.
			if err := UpdateLists(ctx, r); err != nil {
				return err
			}
			err = Run(ctx, r, install)
		}
		return err
	case SUSE:
		switch d.State {
		case Absent:
			return zypper(ctx, r, "remove "+ssh.Quote(d.Name))
		case Latest:
			if err := zypper(ctx, r, "install"+d.recommends(family)+" "+ssh.Quote(d.Name)); err != nil {
				return err
			}
			return zypper(ctx, r, "update"+d.recommends(family)+" "+ssh.Quote(d.Name))
		default:
			spec, old := d.Name, ""
			if d.Version != "" {
				// Without --oldpackage, a pin below the installed version is
				// "Nothing to do." and exit 0, as Ansible's zypper knows.
				spec, old = spec+"="+d.Version, " --oldpackage"
			}
			return zypper(ctx, r, "install"+old+d.recommends(family)+" "+ssh.Quote(spec))
		}
	case APK:
		if d.InstallRecommends != nil {
			return errors.New("install_recommends doesn't apply on Alpine: apk has no recommended packages")
		}
		// --no-cache fetches the index each time, so a fresh host needs no
		// apk update first, and nothing is left in /var/cache/apk.
		switch d.State {
		case Absent:
			return Run(ctx, r, "apk del -q "+ssh.Quote(d.Name))
		case Latest:
			return Run(ctx, r, "apk add -q --no-cache --upgrade "+ssh.Quote(d.Name))
		default:
			// = wants the whole version, -rN included; ~ takes a version
			// without it, such as 2.2.1 for 2.2.1-r0.
			spec := d.Name
			switch {
			case d.Version == "":
			case strings.Contains(d.Version, "-r"):
				spec += "=" + d.Version
			default:
				spec += "~" + d.Version
			}
			return Run(ctx, r, "apk add -q --no-cache "+ssh.Quote(spec))
		}
	}
	return fmt.Errorf("unknown package family %q", family)
}

// exactDeb guards an apt-get command for a name that ends in "+". When no
// package has exactly that name, apt takes the "+" as an instruction, and
// "remove x+" installs x. So the command first checks, with list, that the
// name is a package of its own, and fails the way apt does when it isn't.
func exactDeb(name, list string) string {
	if !strings.HasSuffix(name, "+") {
		return ""
	}
	q := ssh.Quote(name)
	return fmt.Sprintf("%s %s 2>/dev/null | cut -f1 | grep -qxF -- %s || { echo %s >&2; exit 100; }\n", list, q, q, ssh.Quote("E: Unable to locate package "+name))
}

// updateTries and updateMaxWait are Ansible's apt update_cache_retries and
// update_cache_retry_max_delay defaults. A mirror can fail a fetch for a
// moment, with a timeout, a 403 or a 520, and apt-get update then fails
// as a whole, even with another mirror listed.
var updateTries, updateMaxWait, updateJitter = 5, 12 * time.Second, time.Second

// UpdateLists runs apt-get update, trying again when a fetch failed, after
// 1, 2, 4 and 8 seconds, at most updateMaxWait, each with up to a second
// more at random so hosts updating together don't all retry at once, as
// Ansible's apt does.
func UpdateLists(ctx context.Context, r modules.Runner) error {
	var err error
	for try := 0; try < updateTries; try++ {
		if try > 0 {
			wait := min(time.Duration(1<<(try-1))*time.Second, updateMaxWait)
			if updateJitter > 0 {
				wait += time.Duration(rand.Int64N(int64(updateJitter)))
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		}
		if err = Run(ctx, r, "apt-get -q -o DPkg::Lock::Timeout=300 update"); err == nil || !strings.Contains(err.Error(), "Failed to fetch") {
			return err
		}
	}
	return fmt.Errorf("apt-get update failed %d times: %w", updateTries, err)
}

// staleLists reports whether apt failed because its package lists are
// missing, out of date or changed under it, which apt-get update fixes.
func staleLists(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "Unable to locate package") ||
		strings.Contains(msg, "has no installation candidate") ||
		strings.Contains(msg, "Unable to fetch some archives") ||
		strings.Contains(msg, "Can't find a source to download version") ||
		// -t names a release whose lists haven't been fetched yet.
		strings.Contains(msg, "such a release is not available in the sources")
}

// Another apt or dnf can hold the package manager's lock, such as a step
// of another circuit on the same host, or unattended-upgrades or
// dnf-makecache on a host that just booted. apt's DPkg::Lock::Timeout
// doesn't cover the lists lock apt-get update takes, and dnf5 doesn't wait
// for rpm's lock, so Run tries again until lockWait has passed.
var lockWait, lockPoll = 5 * time.Minute, 5 * time.Second

// Run runs a package manager command, waiting out another one's lock.
func Run(ctx context.Context, r modules.Runner, cmd string) error {
	deadline := time.Now().Add(lockWait)
	for {
		err := runOnce(ctx, r, cmd)
		if err == nil || !lockHeld(err) || time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(lockPoll):
		}
	}
}

// zypper runs zypper with args. Exit 102 is success that wants a reboot,
// and 103 is zypper having updated itself, so it runs again once.
func zypper(ctx context.Context, r modules.Runner, args string) error {
	return Run(ctx, r, zypperCommand(args))
}

func zypperCommand(args string) string {
	c := "zypper -n -q " + args
	return c + "; rc=$?; if [ $rc = 103 ]; then " + c + "; rc=$?; fi; [ $rc = 102 ] && rc=0; exit $rc"
}

func lockHeld(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "Could not get lock") || strings.Contains(msg, "transaction lock") ||
		strings.Contains(msg, "System management is locked")
}

func runOnce(ctx context.Context, r modules.Runner, cmd string) error {
	res, err := r.Run(ctx, cmd, nil)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(string(res.Stderr))
		if msg == "" {
			msg = strings.TrimSpace(string(res.Stdout))
		}
		return fmt.Errorf("%s (exit status %d)", msg, res.ExitCode)
	}
	return nil
}
