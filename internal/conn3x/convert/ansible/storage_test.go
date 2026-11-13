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

func TestConvertStorage(t *testing.T) {
	res := convertString(t, `- hosts: db
  tasks:
    - name: data group
      community.general.lvg: { vg: vg0, pvs: "/dev/sdb,/dev/sdc" }
    - name: data volume
      community.general.lvol: { vg: vg0, lv: data, size: 20g, resizefs: true }
    - name: data fs
      community.general.filesystem: { dev: /dev/vg0/data, fstype: xfs, opts: "-L data" }
`)
	hcl := string(res.HCL)
	for _, want := range []string{
		"lvm_volume_group {", `pvs  = ["/dev/sdb", "/dev/sdc"]`,
		"lvm_logical_volume {", `size = "20g"`, "add a filesystem step for /dev/vg0/data",
		"filesystem {", `opts   = ["-L", "data"]`,
	} {
		if !strings.Contains(strings.ToLower(hcl), strings.ToLower(want)) {
			t.Errorf("missing %s:\n%s", want, hcl)
		}
	}
	if res.Converted != 3 || len(res.Review) != 0 {
		t.Errorf("converted %d, review %v", res.Converted, res.Review)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.circuit.hcl"), res.HCL, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, diags := configs.NewParser(afero.NewOsFs()).LoadConfigDir(dir); diags.HasErrors() {
		t.Errorf("the circuit doesn't load: %s\n%s", diags, hcl)
	}

	for task, want := range map[string]string{
		"lvol: { vg: vg0, lv: data, size: +100%FREE }":         "relative to the volume's current one",
		"lvol: { vg: vg0, lv: data, size: 50%PVS }":            "must be a size",
		"lvol: { vg: vg0, lv: data, size: 1g, state: absent }": `state "absent"`,
		"lvg: { vg: vg0, pvs: /dev/sdb, pesize: 32 }":          "sets pesize",
		"filesystem: { dev: /dev/sdb, fstype: ntfs }":          "isn't one Conn3x makes",
	} {
		res := convertString(t, "- hosts: db\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, want) {
			t.Errorf("%s: converted %d, review %+v, want %q", task, res.Converted, res.Review, want)
		}
	}
}
