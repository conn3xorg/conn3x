// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"path/filepath"
	"strings"
	"testing"
)

// A stat probe becomes a conn3x_command data source testing the path the
// way stat's default follow: false does, so a dangling link exists too,
// with no postcondition, as a missing path isn't a failure. X.stat.exists
// and its negation become tests of the exit code (#1344).
func TestConvertRoleStatProbe(t *testing.T) {
	res, err := ConvertRole(filepath.Join("testdata", "role", "stat"))
	if err != nil {
		t.Fatal(err)
	}
	hcl := string(res.Files["main.circuit.hcl"])
	for _, want := range []string{
		"data \"conn3x_command\" \"passwd\" {\n  for_each = var.hosts\n  command  = \"[ -e '/etc/passwd' ] || [ -L '/etc/passwd' ]\"",
		`command  = "[ -e '/tmp/stat-missing' ] || [ -L '/tmp/stat-missing' ]"`,
		"when = data.conn3x_command.passwd[each.key].exit_code == 0\n",
		"when = data.conn3x_command.missing[each.key].exit_code == 0\n",
		"when = data.conn3x_command.passwd[each.key].exit_code == 0 && !(data.conn3x_command.missing[each.key].exit_code == 0)\n",
	} {
		if !strings.Contains(hcl, want) {
			t.Errorf("missing %q:\n%s", want, hcl)
		}
	}
	if strings.Contains(hcl, "postcondition") {
		t.Errorf("a stat probe has no postcondition:\n%s", hcl)
	}
	if res.Converted != 5 || len(res.Review) != 0 {
		t.Errorf("converted %d, review %+v", res.Converted, res.Review)
	}
}

// The other spellings of X.stat.exists that Jinja reads the same convert
// too, as do get_checksum, get_mime and get_attributes set to false,
// which only skip work stat would do (#1412).
func TestRoleStatExistsForms(t *testing.T) {
	yes, no := "data.conn3x_command.x[each.key].exit_code == 0", "data.conn3x_command.x[each.key].exit_code != 0"
	for when, want := range map[string]string{
		"x.stat.exists | bool":       yes,
		"x.stat.exists|bool":         yes,
		"(x.stat.exists | bool)":     yes,
		"not x.stat.exists | bool":   "!(" + yes + ")",
		"x.stat.exists == true":      yes,
		"x.stat.exists==True":        yes,
		"x.stat.exists != false":     yes,
		"x.stat.exists != False":     yes,
		"x.stat.exists is true":      yes,
		"x.stat.exists is not false": yes,
		"x.stat.exists == false":     no,
		"x.stat.exists == False":     no,
		"x.stat.exists != true":      no,
		"x.stat.exists!=True":        no,
		"x.stat.exists is false":     no,
		"x.stat.exists is not true":  no,
	} {
		tasks := "- stat: { path: /etc/x, get_checksum: false, get_mime: no, get_attributes: False }\n  register: x\n- file: { path: /etc/y, state: directory }\n  when: " + when + "\n"
		res, err := ConvertRole(writeRole(t, map[string]string{"tasks/main.yml": tasks}))
		if err != nil {
			t.Fatal(err)
		}
		if hcl := string(res.Files["main.circuit.hcl"]); !strings.Contains(hcl, "when = "+want+"\n") || len(res.Review) != 0 {
			t.Errorf("%s: want when = %s, review %+v:\n%s", when, want, res.Review, hcl)
		}
	}
}

// What stays of a stat probe, each with a reason naming what it can't
// carry: follow: true, any argument but path, a path the converter can't
// fill in or Ansible would expand, a when on any field but exists, a
// command probe's field on a stat probe, and a probe after a change.
func TestRoleStatProbeStays(t *testing.T) {
	for _, c := range []struct{ tasks, want string }{
		{"- stat: { path: /etc/x, follow: true }\n  register: x\n", "sets follow: true"},
		{"- stat: { path: /etc/x, get_checksum: true }\n  register: x\n", "sets get_checksum to something other than false"},
		{"- stat: { path: /etc/x, get_mime: 'false' }\n  register: x\n", "sets get_mime to something other than false"},
		{"- stat: { path: /etc/x, get_md5: false }\n  register: x\n", "sets get_md5, which the converter can't translate yet"},
		{"- stat: { path: /etc/x }\n  register: x\n- file: { path: /etc/y, state: directory }\n  when: x.stat.exists and other_flag\n", "uses when"},
		{"- stat: { path: /etc/x }\n  register: x\n- file: { path: /etc/y, state: directory }\n  when: x.stat.exists | int\n", "uses when"},
		{"- stat: { path: /etc/x }\n  register: x\n- file: { path: /etc/y, state: directory }\n  when: x.stat.exists == 'true'\n", "uses when"},
		{"- stat: { path: /etc/x }\n  register: x\n- file: { path: /etc/y, state: directory }\n  when: x.stat.exists == TRUE\n", "uses when"},
		{"- stat: { path: /etc/x }\n  register: x\n- file: { path: /etc/y, state: directory }\n  when: x.stat.exists is True\n", "uses when"},
		{"- stat: { path: \"{{ app_conf }}\" }\n  register: x\n", `path refers to the role default "app_conf"`},
		{"- stat: { path: ~/.bashrc }\n  register: x\n", "sets a path starting with ~"},
		{"- stat: { path: /etc/x }\n  register: x\n  when: app_conf == '/etc/x'\n", "has a when"},
		{"- stat: { path: /etc/x }\n  register: x\n- file: { path: /etc/y, state: directory }\n  when: x.stat.isdir\n", "reads x.stat.isdir, and the converted stat probe only tests whether the path exists"},
		{"- stat: { path: /etc/x }\n  register: x\n- file: { path: /etc/y, state: directory }\n  when: x.stat.exists and x.stat.mode == '0644'\n", "reads x.stat.mode"},
		{"- stat: { path: /etc/x }\n  register: x\n- file: { path: /etc/y, state: directory }\n  when: x.rc == 0\n", "uses when, which the converter can't translate yet"},
		{"- package: { name: curl }\n- stat: { path: /etc/x }\n  register: x\n", "probes the host after tasks that change it"},
	} {
		res, err := ConvertRole(writeRole(t, map[string]string{"tasks/main.yml": c.tasks, "defaults/main.yml": "app_conf: /etc/app.conf\n"}))
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, r := range res.Review {
			got = append(got, r.Reason)
		}
		if len(got) != 1 || !strings.Contains(got[0], c.want) {
			t.Errorf("%s: want one review with %q, got %q", c.tasks, c.want, got)
		}
	}
}
