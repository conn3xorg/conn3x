// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package lint

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Module sources Dir can't follow are passed over, a module called twice
// is checked once, and a local that leads nowhere is the module's own.
func TestDirModuleEdges(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{
		"main.tf": `module "a" {
  source = "./modules/m"
}
module "again" {
  source = "./modules/m"
}
module "self" {
  source = "./"
}
module "gone" {
  source = "./modules/none"
}
module "file" {
  source = "./notes.txt"
}
module "number" {
  source = 1
}
module "computed" {
  source = var.where
}
module "nosource" {
}
`,
		"notes.txt":         "",
		"broken.tf":         "module \"x\" {\n",
		"node_modules/x.tf": "variable \"a\" {\n  default = \"0.0.0.0\"\n}\n",
		"modules/m/main.circuit.hcl": `# a comment line
circuit "missing" {
  hosts = local.missing
}
circuit "loop" {
  hosts = local.loop
}
circuit "bare" {
  hosts = local
}
circuit "counted" {
  hosts = count.index
}
locals {
  loop = local.loop
}
`,
		"modules/m/broken.tf":             "locals {\n",
		"modules/m/sub/ignored.tf":        "circuit \"c\" {\n  hosts = [\"203.0.113.9\"]\n}\n",
		".terraform/modules/modules.json": "not json",
	})
	found, err := Dir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range found {
		rel, _ := filepath.Rel(dir, f.File)
		got = append(got, filepath.ToSlash(rel)+":"+strconv.Itoa(f.Line)+" "+f.Rule.ID)
	}
	want := "modules/m/main.circuit.hcl:3 C3X102,modules/m/main.circuit.hcl:6 C3X102,modules/m/main.circuit.hcl:9 C3X102"
	if strings.Join(got, ",") != want {
		t.Errorf("findings:\n got %s\nwant %s", strings.Join(got, ","), want)
	}
}
