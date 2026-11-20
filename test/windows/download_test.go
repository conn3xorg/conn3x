// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build windowshost

package windowshost

import (
	"strings"
	"testing"
)

// The 7-Zip MSI the package tests install is downloaded into a temp folder:
// the next plan is clean, a file changed by hand is drift and is fetched
// again, a wrong sha256 fails and leaves dest as it was, and on_remove =
// "delete" removes it.
func TestDownloadFlow(t *testing.T) {
	f := newFlow(t)
	c := connect(t)
	dest := tempDir(t, c) + `\7z.msi`
	hash := func() string {
		return strings.TrimSpace(run(t, c, `param($A) if (Test-Path -LiteralPath $A.p) { (Get-FileHash -LiteralPath $A.p -Algorithm SHA256).Hash.ToLowerInvariant() } else { 'missing' }`, map[string]any{"p": dest}).Text)
	}
	step := func(sum, onRemove string) string {
		return `step "seven" {
    windows_download {
      url       = "` + sevenZipURL + `"
      dest      = "` + strings.ReplaceAll(dest, `\`, `\\`) + `"
      sha256    = "` + sum + `"
      on_remove = "` + onRemove + `"
    }
  }`
	}
	f.cycle(step(sevenZipSum, "delete"), func() {
		run(t, c, `param($A) Set-Content -LiteralPath $A.p -Value 'changed by hand'`, map[string]any{"p": dest})
	})
	if got := hash(); got != sevenZipSum {
		t.Fatalf("dest after the last apply: %s", got)
	}

	// One hex digit wrong: the download is refused and dest is untouched.
	f.write(step("f"+sevenZipSum[1:], "delete"))
	if out := f.expect(1, "apply", "-auto-approve"); !strings.Contains(out, "SHA-256 is "+sevenZipSum) {
		t.Errorf("a wrong sha256:\n%s", out)
	}
	if got := hash(); got != sevenZipSum {
		t.Errorf("dest after a refused download: %s", got)
	}

	f.write(step(sevenZipSum, "delete"))
	f.expect(0, "apply", "-auto-approve")
	f.write(``)
	f.expect(0, "apply", "-auto-approve")
	if got := hash(); got != "missing" {
		t.Errorf("dest after removing the step with on_remove = \"delete\": %s", got)
	}
}
