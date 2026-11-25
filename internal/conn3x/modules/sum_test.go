// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package modules_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/modules/moduletest"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// sum256 prints the bare hash of a file whose name has a backslash, a
// newline or a space, which GNU sha256sum and shasum print with a "\"
// in front when given the name (#1385), and nothing for a missing file.
func TestSum256(t *testing.T) {
	const x = "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"
	dir := t.TempDir()
	// Shadowing command makes sum256 fall back to shasum.
	for _, tool := range []string{"", "command() { return 1; }\n"} {
		if tool != "" {
			if _, err := exec.LookPath("shasum"); err != nil {
				continue
			}
		}
		for _, name := range []string{`a\b c`, "a\nb", "plain"} {
			p := filepath.Join(dir, name)
			if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			res, err := moduletest.Local{}.Run(context.Background(), modules.Sum256+tool+"sum256 "+ssh.Quote(p), nil)
			if got := strings.TrimSpace(string(res.Stdout)); err != nil || res.ExitCode != 0 || got != x {
				t.Errorf("%q%s: %q exit %d %v %s", name, tool, got, res.ExitCode, err, res.Stderr)
			}
		}
	}
	res, _ := moduletest.Local{}.Run(context.Background(), modules.Sum256+"sum256 "+ssh.Quote(filepath.Join(dir, "nope")), nil)
	if len(res.Stdout) != 0 || len(res.Stderr) == 0 {
		t.Errorf("missing file: %q %q", res.Stdout, res.Stderr)
	}
}
