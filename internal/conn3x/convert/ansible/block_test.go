// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/afero"

	"github.com/opentofu/opentofu/internal/configs"
)

// A block's tasks become steps in its place, its rescue becomes rescue
// blocks watching them, and its always becomes always blocks.
func TestConvertBlockRescueAlways(t *testing.T) {
	res := convertString(t, `- hosts: web
  tasks:
    - name: config
      block:
        - name: write config
          copy: { dest: /etc/app.conf, content: "x\n" }
        - block:
            - name: write extra
              copy: { dest: /etc/app.d/extra.conf, content: "y\n" }
      rescue:
        - name: restore config
          command: cp /var/backups/app.conf /etc/app.conf
          args: { creates: /etc/app.conf }
      always:
        - name: mark done
          file: { path: /var/lib/app, state: directory }
`)
	hcl := string(res.HCL)
	for _, want := range []string{
		`step "write_config"`, `step "write_extra"`,
		`rescue "restore_config"`, `always "mark_done"`,
		`watches = [step.write_config, step.write_extra]`,
	} {
		if !strings.Contains(hcl, want) {
			t.Errorf("missing %s:\n%s", want, hcl)
		}
	}
	if res.Converted != 4 || len(res.Review) != 0 {
		t.Errorf("converted %d, review %v", res.Converted, res.Review)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.circuit.hcl"), res.HCL, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, diags := configs.NewParser(afero.NewOsFs()).LoadConfigDir(dir); diags.HasErrors() {
		t.Errorf("the circuit doesn't load: %s\n%s", diags, hcl)
	}
}

func TestConvertBlockLeftForReview(t *testing.T) {
	const copyTask = "copy: { dest: /etc/app.conf, content: \"x\\n\" }"
	for want, tasks := range map[string]string{
		"sets when on a block":    "    - when: x\n      block:\n        - " + copyTask + "\n",
		"ansible_failed_task":     "    - block:\n        - " + copyTask + "\n      rescue:\n        - debug: { msg: \"{{ ansible_failed_task.name }}\" }\n",
		"inside another block":    "    - block:\n        - block:\n            - " + copyTask + "\n          rescue:\n            - " + copyTask + "\n      rescue:\n        - " + copyTask + "\n",
		"nothing for it to watch": "    - block:\n        - command: /bin/true\n      rescue:\n        - " + copyTask + "\n",
	} {
		res := convertString(t, "- hosts: web\n  tasks:\n"+tasks)
		var reasons []string
		for _, r := range res.Review {
			reasons = append(reasons, r.Reason)
		}
		if !strings.Contains(strings.Join(reasons, "\n"), want) {
			t.Errorf("%s: review %v\n%s", want, reasons, res.HCL)
		}
	}
}
