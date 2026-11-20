// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build windowshost

package windowshost

import (
	"strings"
	"testing"
)

// A UTF-16 LE file with \r\n line endings, as Notepad's "Unicode" writes
// it, gets a line: the next plan is clean, removing the line by hand is
// drift and is put back, and the file is still UTF-16 LE with its byte
// order mark and \r\n endings throughout.
func TestLineFlow(t *testing.T) {
	f := newFlow(t)
	c := connect(t)
	file := tempDir(t, c) + `\app.ini`
	run(t, c, `param($A) [IO.File]::WriteAllText($A.p, "[server]`+"`r`n"+`port=80`+"`r`n"+`", [Text.Encoding]::Unicode)`, map[string]any{"p": file})
	describe := func() string {
		return strings.TrimSpace(run(t, c, `param($A)
$b = [IO.File]::ReadAllBytes($A.p)
$text = [Text.Encoding]::Unicode.GetString($b, 2, $b.Length - 2)
$lf = ($text -split "`+"`r`n"+`").Count - 1
$bare = ([regex]::Matches($text, "(?<!`+"`r"+`)`+"`n"+`")).Count
"bom=$('{0:X2}{1:X2}' -f $b[0], $b[1]) crlf=$lf bare_lf=$bare text=$($text -replace "`+"`r`n"+`", '|')"`, map[string]any{"p": file}).Text)
	}
	f.cycle(`step "debug" {
    windows_line {
      path         = "`+strings.ReplaceAll(file, `\`, `\\`)+`"
      line         = "debug=0"
      insert_after = "^\\[server\\]"
    }
  }`, func() {
		run(t, c, `param($A) [IO.File]::WriteAllText($A.p, "[server]`+"`r`n"+`port=80`+"`r`n"+`", [Text.Encoding]::Unicode)`, map[string]any{"p": file})
	})
	if got, want := describe(), "bom=FFFE crlf=3 bare_lf=0 text=[server]|debug=0|port=80|"; got != want {
		t.Errorf("after the last apply:\n got %s\nwant %s", got, want)
	}
}
