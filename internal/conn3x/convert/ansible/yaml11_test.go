// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// Each value is PyYAML 6.0.2's str() of yaml.safe_load("a: " + text)["a"].
func TestYAML11Scalar(t *testing.T) {
	for text, want := range map[string][2]string{
		"yes": {"bool", "True"}, "Yes": {"bool", "True"}, "ON": {"bool", "True"}, "true": {"bool", "True"},
		"no": {"bool", "False"}, "Off": {"bool", "False"}, "FALSE": {"bool", "False"},
		"y": {"", "y"}, "n": {"", "n"}, "yEs": {"", "yEs"},
		"0755": {"int", "493"}, "0x1F": {"int", "31"}, "0b101": {"int", "5"}, "1_000": {"int", "1000"},
		"1:20": {"int", "80"}, "+5": {"int", "5"}, "-0": {"int", "0"}, "10": {"int", "10"}, "08": {"", "08"},
		"1.10": {"float", "1.1"}, "1.0": {"float", "1.0"}, "1.": {"float", "1.0"}, ".5": {"float", "0.5"},
		"1.5e+3": {"float", "1500.0"}, "1.0e+20": {"float", "1e+20"}, "0.00001": {"float", "1e-05"},
		"1:30.5": {"float", "90.5"}, ".inf": {"float", "inf"}, "-.Inf": {"float", "-inf"}, ".NaN": {"float", "nan"},
		"1e5": {"", "1e5"},
		"~":   {"null", "None"}, "null": {"null", "None"}, "": {"null", "None"},
		"present": {"", "present"},
	} {
		if kind, passed := yaml11Scalar(text); kind != want[0] || passed != want[1] {
			t.Errorf("%q: got %s %q, want %s %q", text, kind, passed, want[0], want[1])
		}
	}
}

// A free-text argument Ansible's YAML 1.1 would hand over as other text
// stays for review; the same value quoted converts, and typed arguments
// read their own way.
func TestYAML11FreeText(t *testing.T) {
	const play = "- hosts: all\n  vars: {flag: yes, ver: '1.10'}\n  tasks:\n    - "
	for _, v := range []string{"yes", "on", "true", "1.10", "1.5e+3", "0755", "0x1F", "1_000", "1:20"} {
		for task, key := range map[string]string{
			"copy: {dest: /a, content: " + v + "}":                              "content",
			"lineinfile: {path: /a, line: " + v + "}":                           "line",
			"blockinfile: {path: /a, block: " + v + "}":                         "block",
			"command: {cmd: " + v + ", creates: /x}":                            "cmd",
			"command: {cmd: x, creates: /x}\n      environment: {A: " + v + "}": "environment A",
			"win_environment: {name: A, value: " + v + ", level: machine}":      "value",
		} {
			res := convertString(t, play+task+"\n")
			if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, key+" is the unquoted YAML 1.1") {
				t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
			}
			quoted := strings.Replace(task, ": "+v+",", ": '"+v+"',", 1)
			quoted = strings.Replace(quoted, ": "+v+"}", ": '"+v+"'}", 1)
			if res := convertString(t, play+quoted+"\n"); res.Converted != 1 {
				t.Errorf("%s: converted %d, review %+v", quoted, res.Converted, res.Review)
			}
		}
	}
	// A null module argument is None, not set, and the module reads it its
	// own way; in environment, Ansible writes the text None.
	if res := convertString(t, play+"win_environment: {name: OLD_VAR, value: , level: machine}\n"); res.Converted != 1 || !strings.Contains(string(res.HCL), `state = "absent"`) {
		t.Errorf("null value: converted %d, review %+v:\n%s", res.Converted, res.Review, res.HCL)
	}
	for _, v := range []string{"", "~", "null"} {
		task := "command: {cmd: x, creates: /x}\n      environment: {A: " + v + "}"
		if res := convertString(t, play+task+"\n"); res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, `environment A is the unquoted YAML 1.1 null`) {
			t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
		}
	}
	if res := convertString(t, play+"copy: {dest: /a, content: \"{{ flag }}\"}\n"); res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, "content reads {{ flag }}") {
		t.Errorf("play variable: converted %d, review %+v", res.Converted, res.Review)
	}
	for _, task := range []string{
		"copy: {dest: /a, content: \"{{ ver }}\"}",
		"copy: {dest: /a, content: 10}",
		"copy: {dest: /a, content: 1.5, mode: 0644}",
		"file: {path: /a, state: directory, mode: 0755}",
		"service: {name: nginx, state: started, enabled: yes}",
		"lineinfile: {path: /a, line: x, create: yes}",
		"copy: dest=/a content=yes",
	} {
		if res := convertString(t, "- hosts: all\n  become: yes\n  vars: {ver: '1.10'}\n  tasks:\n    - "+task+"\n"); res.Converted != 1 {
			t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
		}
	}
}
