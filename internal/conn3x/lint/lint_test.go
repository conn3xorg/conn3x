// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package lint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The cases the circuit grader's tests in conn3xorg/web read too, so lint
// and the grader give the same answer for the same code.
func TestGraderCases(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("testdata", "grader-cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Rule, Check, Ext, Text string
		Hit                    bool
	}
	if err := json.Unmarshal(src, &cases); err != nil {
		t.Fatal(err)
	}
	byName := map[string]Rule{}
	for _, r := range Rules {
		byName[r.Name] = r
	}
	for _, c := range cases {
		r, ok := byName[c.Rule]
		if !ok {
			t.Errorf("unknown rule %q", c.Rule)
			continue
		}
		hit := false
		for _, f := range File("case"+c.Ext, []byte(c.Text)) {
			hit = hit || f.Rule == r
		}
		if hit != c.Hit {
			t.Errorf("%s on %q: hit = %v, want %v", c.Rule, c.Text, hit, c.Hit)
		}
	}
}

func TestCommandGuard(t *testing.T) {
	for want, cmd := range map[bool]string{
		true:  `command = "app bootstrap"`,
		false: "command  = \"app bootstrap\"\n      creates = \"/var/lib/app/.done\"",
	} {
		src := "circuit \"c\" {\n  step \"s\" {\n    command {\n      " + cmd + "\n    }\n  }\n}\n"
		got := File("main.circuit.hcl", []byte(src))
		if (len(got) == 1 && got[0].Rule == CommandGuard && got[0].Line == 3) != want {
			t.Errorf("%s: %v", cmd, got)
		}
	}
	// triggers says when to run again, like a reload: left alone.
	src := "circuit \"c\" {\n  step \"reload\" {\n    command {\n      command  = \"systemctl reload app\"\n      triggers = [conn3x_file.c__conf]\n    }\n  }\n}\n"
	for _, f := range File("main.circuit.hcl", []byte(src)) {
		if f.Rule == CommandGuard {
			t.Errorf("a command with triggers: %v", f)
		}
	}
}

// A command that has systemd change a unit fails when systemd re-executes
// mid-apply, which service and service_action ride out; one that only asks
// systemd something doesn't wait on it the same way.
func TestCommandSystemctl(t *testing.T) {
	for cmd, want := range map[string]string{
		`systemctl daemon-reload && systemctl restart 'app.service'`: "daemon-reload",
		`systemctl --user --now restart app`:                         "restart",
		`systemctl reload nginx`:                                     "reload",
		`systemctl is-active --quiet app || exit 1`:                  "",
		`systemctl show -p ActiveState app`:                          "",
		`echo systemctl-restart-later`:                               "",
		`systemctl enable --now app`:                                 "enable --now",
		`systemctl --now disable app`:                                "disable --now",
		`systemctl mask --now app`:                                   "mask --now",
		`systemctl enable app`:                                       "",
		`systemctl try-reload-or-restart app`:                        "try-reload-or-restart",
		`systemctl reload-or-try-restart app`:                        "reload-or-try-restart",
		`sudo systemctl restart app`:                                 "restart",
	} {
		src := "circuit \"c\" {\n  step \"s\" {\n    command {\n      command = \"" + strings.ReplaceAll(cmd, `"`, `\"`) + "\"\n      creates = \"/x\"\n    }\n  }\n}\n"
		var got []Finding
		for _, f := range File("main.circuit.hcl", []byte(src)) {
			if f.Rule == CommandSystemctl {
				got = append(got, f)
			}
		}
		switch {
		case want == "" && len(got) != 0:
			t.Errorf("%s: %v, want nothing", cmd, got)
		case want != "" && (len(got) != 1 || got[0].Line != 4 || !strings.Contains(got[0].Message, "systemctl "+want)):
			t.Errorf("%s: %v, want one finding naming systemctl %s on line 4", cmd, got, want)
		}
	}
	if Failed([]Finding{{Rule: CommandSystemctl}}) {
		t.Error("C3X103 is a warning and shouldn't fail the run")
	}
}

func TestIgnores(t *testing.T) {
	src := strings.Join([]string{
		`# conn3x-lint:ignore C3X003 the caller sets the address; this is the documented default`,
		`default = "0.0.0.0"`,
		`other = "0.0.0.0" # conn3x-lint:ignore C3X003`,
		`# conn3x-lint:ignore C3X002 nothing here to ignore`,
		`x = 1`,
		`# conn3x-lint:ignore C3X999 no such rule`,
	}, "\n")
	findings := File("variables.tf", []byte(src))
	for _, f := range findings {
		if f.Line == 2 {
			t.Errorf("the ignored finding on line 2 was reported: %v", f)
		}
	}
	var ids []string
	for _, f := range findings {
		ids = append(ids, f.Rule.ID)
	}
	// Line 3: the finding is ignored, but the ignore gives no reason.
	// Line 4: an ignore that matches nothing. Line 6: an unknown rule.
	if strings.Join(ids, ",") != "C3X900,C3X900,C3X900" {
		t.Fatalf("findings = %v", findings)
	}
	for _, want := range []string{"gives no reason", "matches nothing", "isn't a rule"} {
		ok := false
		for _, f := range findings {
			ok = ok || strings.Contains(f.Message, want)
		}
		if !ok {
			t.Errorf("no finding says %q: %v", want, findings)
		}
	}
}

// Like the grader, lint leaves out examples/ and test/.
func TestDirSkipsExamplesAndTests(t *testing.T) {
	dir := t.TempDir()
	write := func(p, s string) {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, p), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("variables.tf", "variable \"a\" {\n  default = \"0.0.0.0\"\n}\n")
	write("examples/local/main.tf", "x = \"0.0.0.0\"\n")
	write("test/run.sh", "curl -fsSL https://x | sh\n")
	got, err := Dir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !strings.HasSuffix(got[0].File, "variables.tf") || got[0].Line != 2 || got[0].Column != 14 {
		t.Fatalf("findings = %v", got)
	}
	if !Failed(got) {
		t.Error("an error finding should fail the run")
	}
	if Failed([]Finding{{Rule: CommandGuard}}) {
		t.Error("a warning alone shouldn't fail the run")
	}
}

// A .tofu file can hold circuits as a .tf file can, so it's linted too.
func TestDirLintsTofuFiles(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{"main.tofu": "variable \"a\" {\n  default = \"0.0.0.0\"\n}\n"})
	got, err := Dir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !strings.HasSuffix(got[0].File, "main.tofu") {
		t.Fatalf("findings = %v", got)
	}
}

func write(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, src := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// examples/ and test/ are left out, except code in them that the circuit's
// own code calls as a module, which runs with it.
func TestDirLintsCalledCodeUnderExamplesAndTest(t *testing.T) {
	dir := t.TempDir()
	bad := "variable \"a\" {\n  default = \"0.0.0.0\"\n}\n"
	write(t, dir, map[string]string{
		"main.tf":                    "module \"helper\" {\n  source = \"./test/helper\"\n}\n",
		"test/helper/variables.tf":   bad + "module \"deeper\" {\n  source = \"../../examples/deeper\"\n}\n",
		"examples/deeper/main.tf":    bad,
		"examples/basic/main.tf":     bad,
		"test/fixture/variables.tf":  bad,
		"examples/deeper/sub/x.tf":   bad,
		".terraform/modules/x/x.tf":  bad,
		"examples/deeper/.git/x.tf":  bad,
		"test/helper/scripts/run.sh": "curl https://example.com/install | sh\n",
	})
	found, err := Dir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range found {
		rel, _ := filepath.Rel(dir, f.File)
		got = append(got, filepath.ToSlash(rel)+" "+f.Rule.ID)
	}
	want := "examples/deeper/main.tf C3X003,examples/deeper/sub/x.tf C3X003,test/helper/scripts/run.sh C3X004,test/helper/variables.tf C3X003"
	if strings.Join(got, ",") != want {
		t.Errorf("findings:\n got %s\nwant %s", strings.Join(got, ","), want)
	}
}

// A module the configuration calls, local or installed by init, that names
// its own hosts or keys is reported: it connects with them at plan.
func TestDirReportsConnectionSettingsInCalledModules(t *testing.T) {
	dir := t.TempDir()
	hostile := `circuit "c" {
  hosts = ["203.0.113.9"]
  ssh {
    user                 = var.user
    private_key_file     = "~/.ssh/id_ed25519"
    become_password_file = "~/.sudo-password"
  }
}

data "conn3x_host" "probe" {
  ssh {
    host     = local.hidden
    host_key = "ssh-ed25519 AAAA"
  }
}

locals {
  hidden = "203.0.113.9"
}
`
	// A local that only filters what the caller gave is the caller's, through
	// as many locals as it takes and from another file.
	honest := `circuit "dns" {
  hosts = local.dns
}

locals {
  dns  = { for name, h in local.linux : name => h if local.role[name] == "dns" }
  role = { for name, h in local.linux : name => h.role }
  loop = local.loop
}

circuit "c" {
  hosts = var.hosts
  ssh {
    user             = var.ssh_user
    private_key_file = var.ssh_private_key_file
    host_key         = each.value.host_key
  }
}
`
	write(t, dir, map[string]string{
		// The root's own literals are the operator's to write.
		"main.circuit.hcl":                "circuit \"mine\" {\n  hosts = [\"192.0.2.1\"]\n  ssh {\n    private_key_file = \"~/.ssh/id\"\n  }\n}\n",
		"main.tf":                         "module \"local\" {\n  source = \"./modules/local\"\n}\nmodule \"remote\" {\n  source = \"git::https://example.com/circuit-x?ref=v1\"\n}\nmodule \"honest\" {\n  source = \"./modules/honest\"\n}\nmodule \"mixed\" {\n  source = \"./modules/mixed\"\n}\n",
		"modules/local/main.circuit.hcl":  hostile,
		"modules/honest/main.circuit.hcl": honest,
		"modules/honest/locals.tf":        "locals {\n  linux = { for name, h in var.hosts : name => h if h.os != \"windows\" }\n}\n",
		// A literal anywhere on the way back is still the module's own.
		"modules/mixed/main.circuit.hcl":      "circuit \"c\" {\n  hosts = local.picked\n}\nlocals {\n  picked = { for name, h in local.all : name => h }\n  all    = merge(var.hosts, local.extra)\n  extra  = { spare = \"203.0.113.9\" }\n}\n",
		".terraform/modules/remote/x.tf":      hostile,
		".terraform/modules/modules.json":     `{"Modules":[{"Key":"","Source":"","Dir":"."},{"Key":"remote","Source":"git::https://example.com/circuit-x?ref=v1","Dir":".terraform/modules/remote"},{"Key":"local","Source":"./modules/local","Dir":"modules/local"}]}`,
		".terraform/modules/unlisted/main.tf": hostile,
	})
	found, err := Dir(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := map[string]int{}
	for _, f := range found {
		if f.Rule != ModuleConnection {
			t.Errorf("unexpected finding %s", f)
			continue
		}
		rel, _ := filepath.Rel(dir, f.File)
		count[filepath.ToSlash(rel)]++
	}
	if len(count) != 3 || count["modules/local/main.circuit.hcl"] != 5 || count[".terraform/modules/remote/x.tf"] != 5 || count["modules/mixed/main.circuit.hcl"] != 1 {
		t.Errorf("C3X102 findings by file = %v, want 5 each in the local and the installed module, and 1 for the literal behind two locals", count)
	}
	if Failed(found) {
		t.Error("C3X102 is a warning and shouldn't fail the run")
	}
}
