// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package repo

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules/pkg"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// disk answers file reads from files, by path, takes every other command,
// and fails one holding fail.
type disk struct {
	files map[string]string
	fail  string
	err   error
	ran   []string
	in    []string // what each command in ran got on stdin
	meta  string   // mode, owner and group a read reports; "644 root root" if unset
}

func (d *disk) Run(_ context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	d.ran = append(d.ran, cmd)
	d.in = append(d.in, string(stdin))
	if d.err != nil {
		return ssh.Result{}, d.err
	}
	if d.fail != "" && strings.Contains(cmd, d.fail) {
		return ssh.Result{ExitCode: 1, Stderr: []byte("denied\n")}, nil
	}
	if strings.Contains(cmd, "echo present") {
		meta := d.meta
		if meta == "" {
			meta = "644 root root"
		}
		for p, c := range d.files {
			if strings.Contains(cmd, "route_walk follow '"+p+"'") {
				return ssh.Result{Stdout: []byte("present\n" + meta + "\n" + base64.StdEncoding.EncodeToString([]byte(c)))}, nil
			}
		}
		return ssh.Result{Stdout: []byte("missing\n")}, nil
	}
	return ssh.Result{}, nil
}

func (d *disk) ranAny(s string) bool {
	for _, c := range d.ran {
		if strings.Contains(c, s) {
			return true
		}
	}
	return false
}

// removed reports whether a file.Delete of path ran.
func (d *disk) removed(path string) bool {
	for _, c := range d.ran {
		if isRemove(c, path) {
			return true
		}
	}
	return false
}

// isRemove tells file.Delete's script from a write's, whose trap also has rm -f.
func isRemove(cmd, path string) bool {
	return strings.Contains(cmd, "rm -f -- ") && strings.Contains(cmd, path) && !strings.Contains(cmd, `cat > "$tmp"`) && !strings.Contains(cmd, "echo present")
}

var ctx = context.Background()

func TestInSync(t *testing.T) {
	r := Repo{Name: "nginx", URL: "https://nginx.org/packages/ubuntu", Key: key, Suites: []string{"noble"}}
	files := r.Files(pkg.Deb)
	if ok, err := InSync(ctx, &disk{files: files}, pkg.Deb, r); err != nil || !ok {
		t.Errorf("all in place: %v, %v", ok, err)
	}
	stale := map[string]string{}
	for p, c := range files {
		stale[p] = c
	}
	stale["/etc/apt/sources.list.d/nginx.sources"] = "edited\n"
	if ok, err := InSync(ctx, &disk{files: stale}, pkg.Deb, r); err != nil || ok {
		t.Errorf("an edited file: %v, %v", ok, err)
	}
	if ok, err := InSync(ctx, &disk{}, pkg.Deb, r); err != nil || ok {
		t.Errorf("nothing there: %v, %v", ok, err)
	}
	lost := errors.New("connection lost")
	if _, err := InSync(ctx, &disk{err: lost}, pkg.Deb, r); !errors.Is(err, lost) {
		t.Errorf("connection lost: %v", err)
	}
}

func TestApplyAndDelete(t *testing.T) {
	deb := Repo{Name: "nginx", URL: "https://nginx.org/packages/ubuntu", Key: key, Suites: []string{"noble"}}
	rpm := Repo{Name: "nginx", URL: "https://nginx.org/packages/centos/10/x86_64/", Key: key}

	d := &disk{}
	if err := Apply(ctx, d, pkg.Deb, deb); err != nil {
		t.Fatal(err)
	}
	if !d.ranAny("mkdir -p -m 0755 '/etc/apt/keyrings'") || !d.ranAny("apt-get -q -o DPkg::Lock::Timeout=300 update") {
		t.Errorf("deb apply ran %q", d.ran)
	}
	// dnf reads a new repository on its own next run.
	d = &disk{}
	if err := Apply(ctx, d, pkg.RPM, rpm); err != nil || d.ranAny("apt-get") || !d.ranAny("mkdir -p -m 0755 '/etc/yum.repos.d'") {
		t.Errorf("rpm apply: %v, ran %q", err, d.ran)
	}

	if err := Apply(ctx, &disk{fail: "mkdir -p -m 0755"}, pkg.Deb, deb); err == nil || !strings.HasPrefix(err.Error(), "creating /etc/apt/") || !strings.HasSuffix(err.Error(), ": denied") {
		t.Errorf("mkdir fails: %v", err)
	}
	if err := Apply(ctx, &disk{fail: "cat > \"$tmp\""}, pkg.Deb, deb); err == nil || err.Error() != "denied" {
		t.Errorf("write fails: %v", err)
	}
	if err := Apply(ctx, &disk{fail: "update"}, pkg.Deb, deb); err == nil || err.Error() != "apt-get update: denied (exit status 1)\nthe repository's files are back as they were before this apply" {
		t.Errorf("update fails: %v", err)
	}
	lost := errors.New("connection lost")
	if err := Apply(ctx, &disk{err: lost}, pkg.Deb, deb); !errors.Is(err, lost) {
		t.Errorf("connection lost: %v", err)
	}
	if err := Apply(ctx, &disk{}, pkg.Deb, Repo{Name: "x"}); err == nil {
		t.Error("an invalid repository was written")
	}

	d = &disk{}
	if err := Delete(ctx, d, pkg.Deb, deb); err != nil || !d.ranAny("apt-get") || len(d.ran) != 3 {
		t.Errorf("delete: %v, ran %d", err, len(d.ran))
	}
	if err := Delete(ctx, &disk{fail: "rm -f"}, pkg.RPM, rpm); err == nil {
		t.Error("a failed delete passed")
	}
}

// A refresh that fails leaves the host as it was: the file the apply
// created is removed, the one it changed gets its old content back, and
// the refresh's error is returned. A refresh that passes rolls back nothing.
func TestApplyRollsBackFailedRefresh(t *testing.T) {
	deb := Repo{Name: "nginx", URL: "https://nginx.org/packages/ubuntu", Key: key, Suites: []string{"noble"}}
	suse := Repo{Name: "shells", URL: "https://download.opensuse.org/repositories/shells/15.6/", Key: key}
	for _, c := range []struct {
		name          string
		family        pkg.Family
		r             Repo
		fail, kept    string // kept is the file there before, with old content
		created, want string
	}{
		{"apt", pkg.Deb, deb, "apt-get -q", "/etc/apt/sources.list.d/nginx.sources", "/etc/apt/keyrings/conn3x-nginx.asc", "apt-get update: denied"},
		{"apt key changed", pkg.Deb, deb, "apt-get -q", "/etc/apt/keyrings/conn3x-nginx.asc", "/etc/apt/sources.list.d/nginx.sources", "apt-get update: denied"},
		{"zypper", pkg.SUSE, suse, "zypper --non-interactive refresh", "/etc/pki/rpm-gpg/RPM-GPG-KEY-conn3x-shells", "/etc/zypp/repos.d/shells.repo", "zypper --non-interactive refresh 'shells': denied"},
		{"rpm import", pkg.SUSE, suse, "rpm --import", "/etc/zypp/repos.d/shells.repo", "/etc/pki/rpm-gpg/RPM-GPG-KEY-conn3x-shells", "rpm --import '/etc/pki/rpm-gpg/RPM-GPG-KEY-conn3x-shells': denied"},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := &disk{files: map[string]string{c.kept: "old\n"}, meta: "600 www-data adm", fail: c.fail}
			err := Apply(ctx, d, c.family, c.r)
			if err == nil || !strings.HasPrefix(err.Error(), c.want) || !strings.HasSuffix(err.Error(), "\nthe repository's files are back as they were before this apply") {
				t.Fatalf("err = %v", err)
			}
			if !d.removed(c.created) {
				t.Errorf("%s, which the apply created, not removed: ran %q", c.created, d.ran)
			}
			if d.removed(c.kept) {
				t.Errorf("%s, which was there before, was removed", c.kept)
			}
			// The last write is the rollback's, with the old content, mode and owner.
			last := -1
			for i, cmd := range d.ran {
				if strings.Contains(cmd, c.kept) && strings.Contains(cmd, `cat > "$tmp"`) {
					last = i
				}
			}
			if last < 0 || d.in[last] != "old\n" || !strings.Contains(d.ran[last], `chmod 0600 "$tmp"`) || !strings.Contains(d.ran[last], "www-data") || !strings.Contains(d.ran[last], "adm") {
				t.Errorf("%s not restored: last write %d of %q", c.kept, last, d.ran)
			}
		})
	}

	// The rollback failing too returns both errors.
	d := &disk{fail: "apt-get -q"}
	d2 := &failAfter{disk: d, path: "/etc/apt/keyrings/conn3x-nginx.asc"}
	if err := Apply(ctx, d2, pkg.Deb, deb); err == nil || !strings.Contains(err.Error(), "apt-get update: denied") || !strings.Contains(err.Error(), "putting the repository's files back: read-only") {
		t.Errorf("rollback fails: %v", err)
	}

	d = &disk{}
	if err := Apply(ctx, d, pkg.Deb, deb); err != nil || d.removed("/etc/apt/keyrings/conn3x-nginx.asc") || d.removed("/etc/apt/sources.list.d/nginx.sources") {
		t.Errorf("a refresh that passed: %v, ran %q", err, d.ran)
	}
}

// failAfter is a disk on which removing path fails.
type failAfter struct {
	*disk
	path string
}

func (f *failAfter) Run(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	if isRemove(cmd, f.path) {
		return ssh.Result{ExitCode: 1, Stderr: []byte("read-only\n")}, nil
	}
	return f.disk.Run(ctx, cmd, stdin)
}

func TestReadSourcesAndDisable(t *testing.T) {
	out := "ubuntu\x00ubuntu.sources\x000\x00\x00docker.list\x001\x00\x00"
	r := &canned{res: ssh.Result{Stdout: []byte(out)}}
	id, files, err := ReadSources(ctx, r, pkg.Deb)
	if err != nil || id != "ubuntu" || len(files) != 2 || files[0].Name != "ubuntu.sources" || files[0].Marked || !files[1].Marked {
		t.Errorf("got %q %+v %v", id, files, err)
	}
	if !strings.Contains(r.cmds[0], "cd '/etc/apt/sources.list.d'") || strings.Contains(r.cmds[0], "rpm -qf") {
		t.Errorf("deb listing:\n%s", r.cmds[0])
	}
	r = &canned{res: ssh.Result{Stdout: []byte("rocky\x00rocky.repo\x000\x00rocky-repos \x00")}}
	if _, files, err := ReadSources(ctx, r, pkg.RPM); err != nil || len(files[0].Owners) != 1 || !strings.Contains(r.cmds[0], "rpm -qf") {
		t.Errorf("rpm: %+v, %v", files, err)
	}
	if _, _, err := ReadSources(ctx, &canned{res: ssh.Result{Stdout: []byte("ubuntu\x00a\x00")}}, pkg.Deb); err == nil || !strings.Contains(err.Error(), "unexpected listing") {
		t.Errorf("short listing: %v", err)
	}
	if _, _, err := ReadSources(ctx, &canned{res: ssh.Result{ExitCode: 1, Stderr: []byte("denied\n")}}, pkg.Deb); err == nil || err.Error() != "listing /etc/apt/sources.list.d: denied" {
		t.Errorf("listing fails: %v", err)
	}
	if _, _, err := ReadSources(ctx, &canned{err: errors.New("down")}, pkg.Deb); err == nil {
		t.Error("runner error ignored")
	}

	r = &canned{}
	if err := Disable(ctx, r, pkg.RPM, nil); err != nil || len(r.cmds) != 0 {
		t.Errorf("nothing to disable: %v, ran %q", err, r.cmds)
	}
	if err := Disable(ctx, r, pkg.RPM, []string{"epel.repo", "a b.repo"}); err != nil || !strings.Contains(r.cmds[0], "-- '/etc/yum.repos.d/epel.repo' '/etc/yum.repos.d/a b.repo'") {
		t.Errorf("disable: %v, ran %q", err, r.cmds)
	}
	for _, bad := range []string{"", ".", "..", "x/y"} {
		if err := Disable(ctx, r, pkg.Deb, []string{bad}); err == nil || !strings.Contains(err.Error(), "not a plain file name") {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if err := Disable(ctx, &canned{res: ssh.Result{ExitCode: 1, Stderr: []byte("busy\n")}}, pkg.Deb, []string{"x.list"}); err == nil || !strings.HasSuffix(err.Error(), ": busy") {
		t.Errorf("mv fails: %v", err)
	}
	if err := Disable(ctx, &canned{err: errors.New("down")}, pkg.Deb, []string{"x.list"}); err == nil {
		t.Error("runner error ignored")
	}
}

// canned answers every command with res and err.
type canned struct {
	res  ssh.Result
	err  error
	cmds []string
}

func (c *canned) Run(_ context.Context, cmd string, _ []byte) (ssh.Result, error) {
	c.cmds = append(c.cmds, cmd)
	return c.res, c.err
}
