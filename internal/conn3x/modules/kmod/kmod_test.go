// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package kmod

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

func TestValidate(t *testing.T) {
	if err := (Module{Name: "br_netfilter"}).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (Module{Name: "dummy", Params: []string{"numdummies=2"}}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, m := range []Module{
		{Name: "br netfilter"},
		{Name: "../x"},
		{Name: "dummy", Params: []string{"numdummies"}},
		{Name: "dummy", Params: []string{"n=1; reboot"}},
		{Name: "dummy", Params: []string{"n=1", "n=2"}},
		{Name: "dummy", Params: []string{"n=1"}, Absent: true},
	} {
		if m.Validate() == nil {
			t.Errorf("%+v should be refused", m)
		}
	}
}

func TestInSync(t *testing.T) {
	m := Module{Name: "nf-conntrack", Params: []string{"hashsize=65536", "acct=1"}, Persistent: true}
	if m.kernelName() != "nf_conntrack" || m.LoadPath() != "/etc/modules-load.d/nf-conntrack.conf" || m.OptionsPath() != "/etc/modprobe.d/nf-conntrack.conf" {
		t.Fatalf("names: %s %s %s", m.kernelName(), m.LoadPath(), m.OptionsPath())
	}
	good := Actual{Loaded: true, Params: map[string]string{"hashsize": "65536", "acct": "Y"}, LoadFile: m.loadContent(), OptionsFile: m.optionsContent()}
	if !m.InSync(good) {
		t.Error("a bool param shown as Y matches 1")
	}
	for name, a := range map[string]Actual{
		"not loaded":     {Params: good.Params, LoadFile: good.LoadFile, OptionsFile: good.OptionsFile},
		"other param":    {Loaded: true, Params: map[string]string{"hashsize": "1024", "acct": "Y"}, LoadFile: good.LoadFile, OptionsFile: good.OptionsFile},
		"no boot file":   {Loaded: true, Params: good.Params, OptionsFile: good.OptionsFile},
		"edited options": {Loaded: true, Params: good.Params, LoadFile: good.LoadFile, OptionsFile: "options nf-conntrack hashsize=1\n"},
	} {
		if m.InSync(a) {
			t.Errorf("%s: should be out of sync", name)
		}
	}
	// A param the kernel doesn't show can't be compared; the options file
	// stands in for it.
	if !m.InSync(Actual{Loaded: true, Params: map[string]string{"acct": "Y"}, LoadFile: good.LoadFile, OptionsFile: good.OptionsFile}) {
		t.Error("an unreadable param shouldn't count as different")
	}
	m.Persistent = false
	if !m.InSync(Actual{Loaded: true, Params: good.Params}) {
		t.Error("without persistent, the boot files don't matter")
	}
	gone := Module{Name: "dummy", Absent: true, Persistent: true}
	if !gone.InSync(Actual{}) || gone.InSync(Actual{Loaded: true}) || gone.InSync(Actual{LoadFile: "dummy\n"}) {
		t.Error("absent means unloaded, with no boot files")
	}
	if got := m.optionsContent(); got != "# Written by Conn3x.\noptions nf-conntrack hashsize=65536 acct=1\n" {
		t.Errorf("options = %q", got)
	}
}

// kernel is a host for Read and Apply. It answers the probe from loaded and
// params, reads files natively from files, and takes file writes, deletes
// and modprobe as changes to them.
type kernel struct {
	loaded bool
	params map[string]string // what /sys/module shows
	takes  map[string]string // what a load leaves in params
	files  map[string]string
	fail   string // stderr for a modprobe that fails
	stuck  bool   // modprobe succeeds and changes nothing
	ran    []string
}

var walked = regexp.MustCompile(`route_walk parent '([^']+)'`)

func (k *kernel) ReadFile(_ context.Context, p string) (modules.FileStat, error) {
	c, ok := k.files[p]
	return modules.FileStat{Exists: ok, Regular: ok, Mode: 0o644, Owner: "root", Group: "root", Content: []byte(c)}, nil
}

func (k *kernel) Run(_ context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	k.ran = append(k.ran, cmd)
	switch {
	case strings.Contains(cmd, "/proc/modules"):
		out := ""
		if k.loaded {
			out = "loaded\n"
		}
		for key, v := range k.params {
			out += fmt.Sprintf("param %s %s\n", key, v)
		}
		return ssh.Result{Stdout: []byte(out)}, nil
	// The boot files go first: /etc/modprobe.d names modprobe too.
	case stdin != nil:
		k.files[walked.FindStringSubmatch(cmd)[1]] = string(stdin)
	case strings.Contains(cmd, "rm -f -- "):
		delete(k.files, walked.FindStringSubmatch(cmd)[1])
	case strings.Contains(cmd, "modprobe -"):
		if k.fail != "" {
			return ssh.Result{ExitCode: 1, Stderr: []byte(k.fail)}, nil
		}
		if k.stuck {
			break
		}
		k.loaded = !strings.Contains(cmd, "modprobe -r") || strings.Contains(cmd, "&& modprobe")
		k.params = nil
		if k.loaded {
			k.params = k.takes
		}
	}
	return ssh.Result{}, nil
}

// modprobes is what Apply ran through modprobe.
func (k *kernel) modprobes() []string {
	var m []string
	for _, c := range k.ran {
		if strings.Contains(c, "modprobe -") {
			m = append(m, c)
		}
	}
	return m
}

var ctx = context.Background()

func TestRead(t *testing.T) {
	m := Module{Name: "nf-conntrack", Params: []string{"hashsize=65536", "expect_hashsize=1"}}
	k := &kernel{loaded: true, params: map[string]string{"hashsize": "65536", "expect_hashsize": ""}, files: map[string]string{m.LoadPath(): "nf-conntrack\n"}}
	a, err := Read(ctx, k, m)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Loaded || a.Params["hashsize"] != "65536" || a.LoadFile != "nf-conntrack\n" || a.OptionsFile != "" {
		t.Fatalf("got %+v", a)
	}
	// An empty value still means the kernel shows the param.
	if v, ok := a.Params["expect_hashsize"]; !ok || v != "" {
		t.Errorf("expect_hashsize = %q, %v", v, ok)
	}
	// /sys/module and /proc/modules use the kernel's name, with _.
	if !strings.Contains(k.ran[0], "/sys/module/nf_conntrack/parameters/hashsize") || !strings.Contains(k.ran[0], `"^"'nf_conntrack'" " /proc/modules`) {
		t.Errorf("probe:\n%s", k.ran[0])
	}
}

func TestReadErrors(t *testing.T) {
	k := &kernel{}
	if _, err := Read(ctx, k, Module{Name: "x; reboot"}); err == nil || len(k.ran) != 0 {
		t.Fatalf("an invalid name reached the host: %v, %q", err, k.ran)
	}
	r := &failing{res: ssh.Result{ExitCode: 1, Stderr: []byte("grep: /proc/modules: No such file\n")}}
	if _, err := Read(ctx, r, Module{Name: "dummy"}); err == nil || err.Error() != "grep: /proc/modules: No such file" {
		t.Errorf("non-zero exit: %v", err)
	}
	gone := errors.New("connection lost")
	if _, err := Read(ctx, &failing{err: gone}, Module{Name: "dummy"}); !errors.Is(err, gone) {
		t.Errorf("runner error: %v", err)
	}
}

// failing answers every command with res and err.
type failing struct {
	res ssh.Result
	err error
}

func (f *failing) Run(context.Context, string, []byte) (ssh.Result, error) { return f.res, f.err }

func TestApply(t *testing.T) {
	params := []string{"numdummies=2"}
	for name, c := range map[string]struct {
		m        Module
		k        kernel
		modprobe string // what the one modprobe run holds, "" for none
		files    []string
	}{
		"load": {
			Module{Name: "dummy", Params: params, Persistent: true},
			kernel{takes: map[string]string{"numdummies": "2"}},
			// Each word is quoted, then the whole script again for sh -c.
			`modprobe -- '\''dummy'\'' '\''numdummies=2'\''`,
			[]string{"/etc/modules-load.d/dummy.conf", "/etc/modprobe.d/dummy.conf"},
		},
		"in sync": {
			Module{Name: "dummy", Params: params},
			kernel{loaded: true, params: map[string]string{"numdummies": "2"}},
			"",
			nil,
		},
		"new param": {
			Module{Name: "dummy", Params: params},
			kernel{loaded: true, params: map[string]string{"numdummies": "1"}, takes: map[string]string{"numdummies": "2"}},
			"&& modprobe --",
			nil,
		},
		// A param the kernel doesn't show changed only in the options file.
		"new options file": {
			Module{Name: "dummy", Params: params, Persistent: true},
			kernel{loaded: true, files: map[string]string{"/etc/modprobe.d/dummy.conf": "options dummy numdummies=1\n"}},
			"&& modprobe --",
			[]string{"/etc/modules-load.d/dummy.conf", "/etc/modprobe.d/dummy.conf"},
		},
		"no params drops the options file": {
			Module{Name: "dummy", Persistent: true},
			kernel{loaded: true, files: map[string]string{"/etc/modprobe.d/dummy.conf": "options dummy numdummies=1\n"}},
			"&& modprobe --",
			[]string{"/etc/modules-load.d/dummy.conf"},
		},
		"unload": {
			Module{Name: "dummy", Absent: true, Persistent: true},
			kernel{loaded: true, files: map[string]string{"/etc/modules-load.d/dummy.conf": "dummy\n", "/etc/modprobe.d/dummy.conf": "options dummy\n"}},
			"modprobe -r --",
			nil,
		},
		"already unloaded": {
			Module{Name: "dummy", Absent: true},
			kernel{},
			"",
			nil,
		},
	} {
		k := c.k
		if k.files == nil {
			k.files = map[string]string{}
		}
		if err := Apply(ctx, &k, c.m); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		switch mp := k.modprobes(); {
		case c.modprobe == "" && len(mp) != 0:
			t.Errorf("%s: ran %q, want no modprobe", name, mp)
		case c.modprobe != "" && (len(mp) != 1 || !strings.Contains(mp[0], c.modprobe)):
			t.Errorf("%s: ran %q, want one with %q", name, mp, c.modprobe)
		}
		if !c.m.Persistent {
			continue
		}
		var got []string
		for _, p := range []string{c.m.LoadPath(), c.m.OptionsPath()} {
			if _, ok := k.files[p]; ok {
				got = append(got, p)
			}
		}
		if fmt.Sprint(got) != fmt.Sprint(c.files) {
			t.Errorf("%s: boot files %q, want %q", name, got, c.files)
		}
		if f := k.files[c.m.LoadPath()]; f != "" && f != c.m.loadContent() {
			t.Errorf("%s: load file %q", name, f)
		}
	}
}

func TestApplyErrors(t *testing.T) {
	m := Module{Name: "dummy", Params: []string{"numdummies=2"}}
	for name, c := range map[string]struct {
		m    Module
		k    kernel
		want string
	}{
		"modprobe fails":      {m, kernel{fail: "modprobe: FATAL: Module dummy not found"}, "modprobe dummy: modprobe: FATAL: Module dummy not found"},
		"params didn't take":  {m, kernel{takes: map[string]string{"numdummies": "1"}}, "dummy loaded, but its parameters didn't take; /sys/module/dummy/parameters has what the kernel kept"},
		"still unloaded":      {Module{Name: "dummy"}, kernel{stuck: true}, "dummy isn't loaded after the change"},
		"still loaded":        {Module{Name: "dummy", Absent: true}, kernel{loaded: true, stuck: true}, "dummy isn't unloaded after the change"},
		"refused by Validate": {Module{Name: "dummy", Params: []string{"x"}}, kernel{}, `params "x" must be key=value`},
	} {
		k := c.k
		k.files = map[string]string{}
		err := Apply(ctx, &k, c.m)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	k := &kernel{}
	if err := Apply(ctx, k, Module{Name: "dummy", Params: []string{"x"}}); err == nil || len(k.ran) != 0 {
		t.Errorf("a refused module reached the host: %v, %q", err, k.ran)
	}
}
