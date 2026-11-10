// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"path"
	"strings"
	"testing"

	testing_command "github.com/opentofu/opentofu/internal/command/testing"
	"github.com/opentofu/opentofu/internal/command/workdir"
)

// A run with idempotent = true passes when the second plan is empty, and
// otherwise names what it would change. Either way, what it made is
// destroyed.
func TestTest_Idempotent(t *testing.T) {
	for dir, want := range map[string]struct {
		code   int
		stdout string
		stderr string
	}{
		"idempotent_pass": {0, "1 passed, 0 failed.", ""},
		"idempotent_fail": {1, "0 passed, 1 failed.", "- test_resource.always would be updated in-place"},
	} {
		t.Run(dir, func(t *testing.T) {
			td := t.TempDir()
			testCopyDir(t, testFixturePath(path.Join("test", dir)), td)
			t.Chdir(td)

			provider := testing_command.NewProvider(nil)
			view, done := testView(t)
			c := &TestCommand{
				WorkingDir:       workdir.NewDir("."),
				testingOverrides: metaOverridesForProvider(provider.Provider),
				View:             view,
			}
			code := c.Run([]string{"-no-color"})
			output := done(t)

			if code != want.code {
				t.Errorf("status %d, want %d:\n%s", code, want.code, output.All())
			}
			if !strings.Contains(output.Stdout(), want.stdout) {
				t.Errorf("stdout lacks %q:\n%s", want.stdout, output.Stdout())
			}
			stderr := output.Stderr()
			if want.stderr == "" && stderr != "" {
				t.Errorf("unexpected stderr:\n%s", stderr)
			}
			if want.stderr != "" && (!strings.Contains(stderr, "Error: Not idempotent") || !strings.Contains(stderr, want.stderr) || strings.Contains(stderr, "test_resource.foo")) {
				t.Errorf("stderr doesn't name just the changed resource:\n%s", stderr)
			}
			if provider.ResourceCount() > 0 {
				t.Errorf("should have deleted all resources on completion but left %v", provider.ResourceString())
			}
		})
	}
}
