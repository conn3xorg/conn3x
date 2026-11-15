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
	// Every resource object in the -json stream names the circuit step and
	// host it is, for UIs and CI tools reading the stream (#526).
	"internal/command/jsonentities/resource_addr.go": {
		{"ResourceKey     ctyjson.SimpleJSONValue `json:\"resource_key\"`", "ResourceKey     ctyjson.SimpleJSONValue `json:\"resource_key\"`\n\tConn3x *jsonstep.Step `json:\"conn3x,omitempty\"`"},
		{"ResourceKey:     resourceKey,", "ResourceKey:     resourceKey,\n\t\tConn3x: jsonstep.Of(addr),"},
		{"import (", "import (\n\t\"github.com/opentofu/opentofu/internal/conn3x/jsonstep\""},
	},
	// A plan, show or state show prints a multi-line string as it is, line
	// by line. Hosts write many of them, a file's content for one, so
	// control characters in them are written out as escapes. A single-line
	// string is already printed quoted.
	"internal/command/jsonformat/computed/renderers/string.go": {
		{"String:      strings.TrimSpace(str),", "String:      termsafe.Escape(strings.TrimSpace(str)),"},
		{"func (e evaluatedString) RenderSimple() string {", `// conn3xLines is the string as the lines of a line-by-line diff, where a
// single-line string is printed unquoted beside a multi-line one.
func (e evaluatedString) conn3xLines() []string {
	if e.IsNull {
		return []string{e.String}
	}
	return strings.Split(termsafe.Escape(e.String), "\n")
}

func (e evaluatedString) RenderSimple() string {`},
		{"import (", "import (\n\t\"github.com/opentofu/opentofu/internal/conn3x/termsafe\""},
	},
	// An error or warning often quotes a host: what a failed command
	// printed, or a refused read. With color on, upstream swaps the C0
	// control characters in it for pictures; without, it prints them as
	// they are. Both now write every control character out as an escape.
	"internal/command/format/diagnostic.go": {
		{"func DiagnosticFromJSON(diag *jsonentities.Diagnostic, color *colorstring.Colorize, width int) string {", `// conn3xSafe is diag with the control characters in its text escaped.
func conn3xSafe(diag *jsonentities.Diagnostic) *jsonentities.Diagnostic {
	if diag == nil {
		return nil
	}
	safe := *diag
	safe.Summary, safe.Detail = termsafe.Escape(diag.Summary), termsafe.Escape(diag.Detail)
	return &safe
}

func DiagnosticFromJSON(diag *jsonentities.Diagnostic, color *colorstring.Colorize, width int) string {
	diag = conn3xSafe(diag)`},
		{"func DiagnosticPlainFromJSON(diag *jsonentities.Diagnostic, width int) string {", "func DiagnosticPlainFromJSON(diag *jsonentities.Diagnostic, width int) string {\n\tdiag = conn3xSafe(diag)"},
		{"diag.Description().Summary)", "termsafe.Escape(diag.Description().Summary))"},
		{"import (", "import (\n\t\"github.com/opentofu/opentofu/internal/conn3x/termsafe\""},
	},
	"internal/command/jsonformat/computed/renderers/primitive.go": {
		{`beforeLines := strings.Split(beforeString.String, "\n")`, "beforeLines := beforeString.conn3xLines()"},
		{`afterLines := strings.Split(afterString.String, "\n")`, "afterLines := afterString.conn3xLines()"},
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
