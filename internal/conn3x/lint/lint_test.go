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
	if got := File("main.circuit.hcl", []byte(src)); len(got) != 0 {
		t.Errorf("a command with triggers: %v", got)
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
