// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package brand

import (
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"strings"
)

// patches replace upstream code that rewriting literals can't reach, by
// file. Each old string is matched after the literal rewrite and must occur
// exactly once, so an upstream change that moves it fails the build.
var patches = map[string][][2]string{
	// The version message that starts every -json stream names the Conn3x
	// release, and a conn3x field carries its version beside OpenTofu's.
	"internal/command/views/json_view.go": {
		{`fmt.Sprintf("Conn3x %s", version)`, `conn3xversion.String()`},
		{`"tofu", version,`, `"tofu", version, "conn3x", conn3xversion.Version,`},
		{"import (", "import (\n\tconn3xversion \"github.com/opentofu/opentofu/internal/conn3x/version\""},
	},
}

// patch applies patches, starting from each file's branded copy when there
// is one, and records the results in the overlay.
func patch(root, outDir string, replace map[string]string) error {
	for rel, edits := range patches {
		orig := filepath.Join(root, filepath.FromSlash(rel))
		from := orig
		if branded, ok := replace[orig]; ok {
			from = branded
		}
		src, err := os.ReadFile(from)
		if os.IsNotExist(err) {
			continue // a partial tree in tests
		}
		if err != nil {
			return err
		}
		s := string(src)
		for _, e := range edits {
			if n := strings.Count(s, e[0]); n != 1 {
				return fmt.Errorf("%s: expected %q once, found it %d times", rel, e[0], n)
			}
			s = strings.Replace(s, e[0], e[1], 1)
		}
		out, err := format.Source([]byte(s))
		if err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
		dest := filepath.Join(outDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dest, out, 0o644); err != nil {
			return err
		}
		replace[orig] = dest
	}
	return nil
}
