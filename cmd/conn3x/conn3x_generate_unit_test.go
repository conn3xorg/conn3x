// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh/sshtest"
)

// brGenHost is a host over SSH whose shell is answer, and the flags that
// reach it. A command that is the PowerShell stub gets windows instead, as
// the stub's result line.
func brGenHost(t *testing.T, answer func(cmd string) (string, int), windows any) generateOptions {
	t.Helper()
	t.Setenv("CONN3X_AGENT", "off")
	s := sshtest.New(t)
	s.SetExec(func(cmd string, _ []byte) (string, int) {
		if cmd == ps.Command {
			b, _ := json.Marshal(map[string]any{"ok": true, "value": windows})
			return "conn3x-result:" + base64.StdEncoding.EncodeToString(b) + "\r\n", 0
		}
		return answer(strings.ReplaceAll(cmd, `'\''`, "'"))
	})
	return generateOptions{host: s.Host, port: s.Port, user: "root", keyFile: s.KeyFile(t), knownHosts: s.KnownHosts(t)}
}

// brReplies answers a command with the reply of the first key it contains;
// a reply starting "!" fails. Anything else exits 0 silently.
func brReplies(pairs ...string) func(string) (string, int) {
	return func(cmd string) (string, int) {
		for i := 0; i+1 < len(pairs); i += 2 {
			if strings.Contains(cmd, pairs[i]) {
				if msg, failed := strings.CutPrefix(pairs[i+1], "!"); failed {
					return msg, 1
				}
				return pairs[i+1], 0
			}
		}
		return "", 0
	}
}

const brTimers = "\x1ebackup\x1f[Timer]\nOnCalendar=daily\n\x1f[Service]\nExecStart=/usr/local/bin/backup.sh\n\x1f\n" +
	"\x1ejitter\x1f[Timer]\nOnCalendar=hourly\nRandomizedDelaySec=5m\n\x1f[Service]\nExecStart=/bin/true\n\x1f\n"

// Without -match, each object prints on a line of its own, with its value
// for a kind that has one, and why a timer can't be adopted.
func TestGenerateStepsLists(t *testing.T) {
	o := brGenHost(t, brReplies("*.timer", brTimers, "cat /etc/sysctl.conf", "vm.swappiness = 10\n"), nil)
	for kind, want := range map[string]string{
		"timers": "backup = daily: /usr/local/bin/backup.sh\njitter  (can't adopt: [Timer] RandomizedDelaySec is something a timer step doesn't set)\n",
		"sysctl": "vm.swappiness = 10\n",
	} {
		var out, errOut bytes.Buffer
		if code := runGenerateSteps(context.Background(), o, kind, "", &out, &errOut); code != 0 || out.String() != want {
			t.Errorf("%s: exit %d, %q, %q", kind, code, out.String(), errOut.String())
		}
	}
}

// With -match, each matching timer prints as a step with the host's
// values; one that can't be adopted is reported, and the run exits 1.
func TestGenerateStepsTimers(t *testing.T) {
	o := brGenHost(t, brReplies("*.timer", brTimers), nil)
	var out, errOut bytes.Buffer
	if code := runGenerateSteps(context.Background(), o, "timers", "backup", &out, &errOut); code != 0 {
		t.Fatalf("exit %d, %q", code, errOut.String())
	}
	for _, want := range []string{`step "backup" {`, "import = true", "timer {", `name        = "backup"`, `on_calendar = "daily"`, `command     = "/usr/local/bin/backup.sh"`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("%q isn't in\n%s", want, out.String())
		}
	}
	out.Reset()
	errOut.Reset()
	if code := runGenerateSteps(context.Background(), o, "timers", "*", &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "timer jitter isn't adopted") || !strings.Contains(errOut.String(), "1 of 2 matching timers couldn't be read") || !strings.Contains(out.String(), `step "backup"`) {
		t.Errorf("exit %d, out %q, err %q", code, out.String(), errOut.String())
	}
	for match, want := range map[string]string{
		"nope*": `-match "nope*" matches none of the 2 timers`,
		"[":     `-match "[" isn't a valid glob`,
	} {
		errOut.Reset()
		if code := runGenerateSteps(context.Background(), o, "timers", match, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), want) {
			t.Errorf("%s: exit %d, %q", match, code, errOut.String())
		}
	}
}

// A Windows step holds the name alone, and names that would clash get a
// number, so every step pasted in is its own.
func TestGenerateStepsWindows(t *testing.T) {
	o := brGenHost(t, brReplies(), map[string]any{"names": []string{"Ops", "ops", "Web"}})
	var out, errOut bytes.Buffer
	if code := runGenerateSteps(context.Background(), o, "windows_groups", "Ops,ops", &out, &errOut); code != 0 {
		t.Fatalf("exit %d, %q", code, errOut.String())
	}
	got := out.String()
	for _, want := range []string{`step "ops" {`, `step "ops_2" {`, `name = "Ops"`, `name = "ops"`, "windows_group {", "\n\nstep"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q isn't in\n%s", want, got)
		}
	}
	if strings.Contains(got, "Web") {
		t.Errorf("printed a group -match left out:\n%s", got)
	}
}

// A package that can't be read is counted and the others still print.
func TestGenerateStepsReportsWhatItCantRead(t *testing.T) {
	o := brGenHost(t, brReplies("cat /etc/os-release", "ID=debian\n", "dpkg --print-architecture", "amd64\nnginx\tamd64\t1.24\n", "dpkg-query", "!dpkg: database locked"), nil)
	var out, errOut bytes.Buffer
	if code := runGenerateSteps(context.Background(), o, "packages", "*", &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "1 of 1 matching packages couldn't be read") {
		t.Errorf("exit %d, out %q, err %q", code, out.String(), errOut.String())
	}
}

// A file reads into a step with its content and the host's owner and mode.
func TestGenerateStepReadsAFile(t *testing.T) {
	o := brGenHost(t, brReplies("echo present", "present\n0640 root adm\n"+base64.StdEncoding.EncodeToString([]byte("welcome\n"))), nil)
	o.module, o.args = "file", []string{"path=/etc/motd"}
	var out, errOut bytes.Buffer
	if code := runGenerateStep(context.Background(), o, &out, &errOut); code != 0 {
		t.Fatalf("exit %d, %q", code, errOut.String())
	}
	got := out.String()
	for _, want := range []string{`step "etc_motd" {`, "import = true", `path    = "/etc/motd"`, `group   = "adm"`, `mode    = "0640"`, "welcome"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q isn't in\n%s", want, got)
		}
	}
	// -write-only keeps the content out, and -name names the step.
	out.Reset()
	o.writeOnly, o.name = true, "motd"
	if code := runGenerateStep(context.Background(), o, &out, &errOut); code != 0 || strings.Contains(out.String(), "welcome") || !strings.Contains(out.String(), `step "motd"`) || !strings.Contains(out.String(), contentPlaceholder) {
		t.Errorf("write-only: exit %d, %q, %q", code, out.String(), errOut.String())
	}
}

// manual_packages lists only what was installed by hand: on Debian and
// Ubuntu, apt's manual marks without the base system or anything another
// package needs; on the Red Hat family, dnf's user-installed list, where a
// package of another architecture keeps its name.
func TestGenerateStepsManualPackages(t *testing.T) {
	for name, tc := range map[string]struct {
		replies []string
		want    string
	}{
		"deb": {[]string{
			"cat /etc/os-release", "ID=ubuntu\nID_LIKE=debian\n",
			"dpkg --print-architecture", "amd64\nbase-files\tamd64\t13ubuntu10\nlibc6\tamd64\t2.39-0ubuntu8\nlibc6\ti386\t2.39-0ubuntu8\nnginx\tamd64\t1.24.0-2ubuntu7\n",
			"apt-mark showmanual", "base-files\nlibc6:i386\nnginx\n@@@\n" +
				"ii \tbase-files\tyes\trequired\t, , \n" +
				"ii \tlibc6\tno\trequired\t, , \n" +
				"ii \tnginx\tno\toptional\tlibc6 (>= 2.34), , \n",
		}, "nginx\n"},
		"rpm": {[]string{
			"cat /etc/os-release", "ID=rocky\nID_LIKE=\"rhel centos fedora\"\n",
			"rpm -qa", "x86_64\nbash\tx86_64\t0:5.2.26-6.el10\nglibc\ti686\t0:2.39-37.el10\npostgresql-server\tx86_64\t0:16.8-2.el10\n",
			"repoquery --userinstalled", "glibc\n\npostgresql-server\n\n",
		}, "glibc.i686\npostgresql-server\n"},
	} {
		o := brGenHost(t, brReplies(tc.replies...), nil)
		var out, errOut bytes.Buffer
		if code := runGenerateSteps(context.Background(), o, "manual_packages", "", &out, &errOut); code != 0 || out.String() != tc.want {
			t.Errorf("%s: exit %d, %q, %q", name, code, out.String(), errOut.String())
		}
	}
}

// cron lists each /etc/cron.d file with its schedule and command, or why a
// cron step can't adopt it, and -match prints a step from what it read.
func TestGenerateStepsCron(t *testing.T) {
	files := "\x1ebackup\x1f# nightly\n0 2 * * * deploy /usr/local/bin/backup.sh\n" +
		"\x1ee2scrub_all\x1fSHELL=/bin/bash\n10 3 * * 0 root test -e /run/systemd/system || /sbin/e2scrub_all\n"
	o := brGenHost(t, brReplies("/etc/cron.d/*", files), nil)
	var out, errOut bytes.Buffer
	if code := runGenerateSteps(context.Background(), o, "cron", "", &out, &errOut); code != 0 ||
		out.String() != "backup = 0 2 * * *: /usr/local/bin/backup.sh\ne2scrub_all  (can't adopt: sets SHELL, which a cron step doesn't)\n" {
		t.Fatalf("list: exit %d, %q, %q", code, out.String(), errOut.String())
	}
	out.Reset()
	if code := runGenerateSteps(context.Background(), o, "cron", "backup", &out, &errOut); code != 0 {
		t.Fatalf("match: exit %d, %q", code, errOut.String())
	}
	for _, want := range []string{`cron {`, `name     = "backup"`, `schedule = "0 2 * * *"`, `user     = "deploy"`, `command  = "/usr/local/bin/backup.sh"`, `import = true`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("step is missing %s:\n%s", want, out.String())
		}
	}
}
