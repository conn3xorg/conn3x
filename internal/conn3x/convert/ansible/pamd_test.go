// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// community.general.pamd becomes a pam_rule step for each of its six
// states. What could change more than the play stays for review.
func TestConvertPamd(t *testing.T) {
	play := filepath.Join(t.TempDir(), "play.yml")
	convert := func(task string) Result {
		t.Helper()
		if err := os.WriteFile(play, []byte("- hosts: all\n  tasks:\n    - "+task+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		res, err := Convert(play)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	for task, want := range map[string][]string{
		// The issue's example: faillock before pam_unix.
		`community.general.pamd: {name: system-auth, type: auth, control: required, module_path: pam_unix.so, state: before, new_type: auth, new_control: required, new_module_path: pam_faillock.so}`: {
			"pam_rule {", `service = "system-auth"`, `module  = "pam_faillock.so"`, `before  = "auth required pam_unix.so"`, "inserts it once",
		},
		`pamd: {name: common-auth, type: auth, control: "[success=1 default=ignore]", module_path: pam_unix.so, state: after, new_type: auth, new_control: optional, new_module_path: pam_cap.so}`: {
			`after   = "auth [success=1 default=ignore] pam_unix.so"`,
		},
		`pamd: {name: sshd, type: auth, control: required, module_path: pam_env.so, module_arguments: "readenv=1, user_readenv=0 envfile=/etc/environment"}`: {
			`arguments = ["readenv=1", "user_readenv=0", "envfile=/etc/environment"]`, "fails instead",
		},
		`pamd: {name: sshd, type: auth, control: required, module_path: pam_env.so, module_arguments: []}`: {
			"arguments = []",
		},
		`pamd: {name: system-auth, type: auth, control: required, module_path: pam_tally2.so, new_module_path: pam_faillock.so, state: updated}`: {
			`module  = "pam_faillock.so"`, `replace = "auth required pam_tally2.so"`,
		},
		`pamd: {name: common-password, type: password, control: "[success=1 default=ignore]", module_path: pam_unix.so, module_arguments: remember=5, state: args_present, backup: true}`: {
			`state     = "args_present"`, `arguments = ["remember=5"]`, "backup    = true",
		},
		`pamd: {name: common-auth, path: /etc/pam.d, type: auth, control: "[success=1 default=ignore]", module_path: pam_unix.so, module_arguments: [nullok], state: args_absent}`: {
			`state     = "args_absent"`, `arguments = ["nullok"]`,
		},
		`pamd: {name: login, path: /usr/local/etc/pam.d, type: session, control: optional, module_path: pam_motd.so, state: absent}`: {
			`path    = "/usr/local/etc/pam.d"`, `state   = "absent"`,
		},
	} {
		res := convert(task)
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%s: converted %d, review %+v\n%s", task, res.Converted, res.Review, res.HCL)
			continue
		}
		for _, w := range want {
			if !strings.Contains(string(res.HCL), w) {
				t.Errorf("%s: missing %q:\n%s", task, w, res.HCL)
			}
		}
		if strings.Contains(string(res.HCL), `path    = "/etc/pam.d"`) || strings.Contains(task, "state: absent") && strings.Contains(string(res.HCL), "fails instead") {
			t.Errorf("%s: default path spelled out, or the missing-rule note on absent:\n%s", task, res.HCL)
		}
	}

	for task, reason := range map[string]string{
		`pamd: {name: sshd, type: auth, control: required, module_path: pam_env.so, state: before, new_type: auth, new_control: required, new_module_path: pam_faillock.so, module_arguments: preauth}`: "gives them only to a rule it inserts",
		`pamd: {name: sshd, type: auth, control: required, module_path: pam_tally2.so, new_module_path: pam_faillock.so, module_arguments: [deny=3]}`:                                                   "changes a rule and sets its arguments",
		`pamd: {name: sshd, type: auth, control: required, module_path: pam_env.so, state: after, new_module_path: pam_faillock.so}`:                                                                    "needs new_type, new_control and new_module_path",
		`pamd: {name: sshd, type: auth, control: required, module_path: pam_env.so, state: args_present}`:                                                                                               "needs module_arguments",
		`pamd: {name: sshd, type: auth, control: required, module_path: pam_env.so, state: args_present, module_arguments: ["[a b]"]}`:                                                                  "bracketed module argument",
		`pamd: {name: sshd, type: auth, control: required, module_path: pam_env.so, state: args_present, module_arguments: ["a=b=c"]}`:                                                                  "more than one =",
		`pamd: {name: sshd, type: auth, control: "[success=1  default=ignore]", module_path: pam_unix.so, state: absent}`:                                                                               "matches only as written",
		`pamd: {name: sshd, type: auth, control: definitive, module_path: pam_unix.so, state: absent}`:                                                                                                  "can't be a pam_rule step",
		`pamd: {name: sshd, type: auth, control: required, module_path: pam_env.so, state: replaced}`:                                                                                                   `state "replaced"`,
		`pamd: {type: auth, control: required, module_path: pam_env.so, state: absent}`:                                                                                                                 "needs name",
		`pamd: {name: sshd, control: required, module_path: pam_env.so, state: absent}`:                                                                                                                 "needs type, control and module_path",
		`pamd: {name: "{{ svc }}", type: auth, control: required, module_path: pam_env.so, state: absent}`:                                                                                              "svc",
		`pamd: name=sshd type=auth control=required module_path=pam_env.so state=absent`:                                                                                                                "key=value text",
	} {
		res := convert(task)
		if res.Converted != 0 || !strings.Contains(reasons(res), reason) {
			t.Errorf("%s: converted %d, review %q, want %q\n%s", task, res.Converted, reasons(res), reason, res.HCL)
		}
	}
}
