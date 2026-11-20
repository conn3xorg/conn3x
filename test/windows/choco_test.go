// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build windowshost

package windowshost

import (
	"context"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows"
)

// chocoFeed packs a package in two versions into a folder feed, as the MSI
// tests build their MSI, and removes the package however the test ends.
func chocoFeed(t *testing.T, id string) string {
	t.Helper()
	c := connect(t)
	feed := strings.TrimSpace(run(t, c, `param($A)
$feed = Join-Path $env:TEMP ('c3xfeed' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$null = New-Item -ItemType Directory -Path $feed
foreach ($v in '1.0.0', '2.0.0') {
  $d = Join-Path $feed "src-$v"
  $null = New-Item -ItemType Directory -Path (Join-Path $d 'tools') -Force
  Set-Content -LiteralPath (Join-Path $d "$($A.id).nuspec") -Encoding UTF8 -Value @"
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd">
  <metadata><id>$($A.id)</id><version>$v</version><title>$($A.id)</title><authors>conn3x</authors><description>test</description></metadata>
  <files><file src="tools\**" target="tools" /></files>
</package>
"@
  Set-Content -LiteralPath (Join-Path $d 'tools\chocolateyInstall.ps1') -Value "Write-Host $v"
  Push-Location -LiteralPath $d
  & "$env:ChocolateyInstall\choco.exe" pack --out $feed --limit-output | Out-Null
  Pop-Location
}
$feed`, map[string]any{"id": id}).Text)
	t.Cleanup(func() {
		run(t, c, `param($A)
$choco = "$env:ChocolateyInstall\choco.exe"
& $choco pin remove -n $A.id --limit-output | Out-Null
& $choco uninstall $A.id -y --limit-output | Out-Null
Remove-Item -LiteralPath $A.feed -Recurse -Force -ErrorAction SilentlyContinue`, map[string]any{"id": id, "feed": feed})
	})
	return feed
}

// Installed pinned at 1.0.0 from a folder feed, unpinned by hand and pinned
// again, moved to 2.0.0 through its pin, and removed.
func TestChocoFlow(t *testing.T) {
	f := newFlow(t)
	c := connect(t)
	ctx := context.Background()
	id := "C3xChoco" + suffix()
	feed := chocoFeed(t, id)
	hcl := func(version, state string) string {
		body := `      name    = "` + strings.ToLower(id) + `"` + "\n"
		if state == "absent" {
			body += `      state   = "absent"` + "\n"
		} else {
			body += `      version = "` + version + `"
      source  = "` + strings.ReplaceAll(feed, `\`, `\\`) + `"
      pinned  = true` + "\n"
		}
		return "step \"pkg\" {\n    windows_choco_package {\n" + body + "    }\n  }"
	}
	read := func() windows.ActualChoco {
		t.Helper()
		a, err := windows.ReadChoco(ctx, c, id)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}

	// The name is given in lower case; the package keeps its own.
	f.cycle(hcl("1.0", ""), func() {
		run(t, c, `param($A) & "$env:ChocolateyInstall\choco.exe" pin remove -n $A.id --limit-output | Out-Null`, map[string]any{"id": id})
	})
	if a := read(); !a.Installed || a.Version != "1.0.0" || !a.Pinned {
		t.Fatalf("after 1.0: %+v", a)
	}

	f.write(hcl("2.0.0", ""))
	f.expect(2, "plan", "-detailed-exitcode")
	f.expect(0, "apply", "-auto-approve")
	f.expect(0, "plan", "-detailed-exitcode")
	if a := read(); a.Version != "2.0.0" || !a.Pinned {
		t.Fatalf("after 2.0.0, through the pin: %+v", a)
	}

	f.write(hcl("", "absent"))
	f.expect(0, "apply", "-auto-approve")
	f.expect(0, "plan", "-detailed-exitcode")
	if a := read(); a.Installed {
		t.Fatalf("after absent: %+v", a)
	}
}
