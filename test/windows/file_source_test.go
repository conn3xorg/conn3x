// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build windowshost

package windowshost

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows"
)

// A copy of a file already on the host is byte for byte, stops at a missing
// source before anything is made, and never reads through a link (#1377).
func TestFileCopiesSource(t *testing.T) {
	c := connect(t)
	ctx := context.Background()
	dir := tempDir(t, c)
	src, dest := dir+`\app.conf.sample`, dir+`\app.conf`
	exists := func(p string) bool {
		t.Helper()
		return strings.TrimSpace(run(t, c, `param($A) Test-Path -LiteralPath $A.p`, map[string]any{"p": p}).Text) == "True"
	}

	err := windows.ApplyFileCopy(ctx, c, dest, src, nil)
	if err == nil || !strings.Contains(err.Error(), "source_path "+src+" doesn't exist on the host") {
		t.Fatalf("missing source: %v", err)
	}
	if exists(dest) {
		t.Fatal("a missing source still made the file")
	}

	const content = "listen = 80\r\n\x00'$(x)\"\n"
	run(t, c, `param($A) [IO.File]::WriteAllBytes($A.p, [Convert]::FromBase64String($A.b))`, map[string]any{"p": src, "b": b64(content)})
	if err := windows.ApplyFileCopy(ctx, c, dest, src, nil); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(fileText(t, c, dest)); got != b64(content) {
		t.Errorf("copy bytes differ: %s", got)
	}
	a, err := windows.ReadPath(ctx, c, dest, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	s, err := windows.ReadPath(ctx, c, src, nil, true)
	if err != nil || a.SHA256 == "" || a.SHA256 != s.SHA256 {
		t.Fatalf("hashes: copy %+v, source %+v, %v", a, s, err)
	}

	// With rules, the copy has them, not the source's.
	if err := windows.ApplyFileCopy(ctx, c, dir+`\secret.conf`, src, windows.SecretEntries); err != nil {
		t.Fatal(err)
	}
	r, err := windows.ReadPath(ctx, c, dir+`\secret.conf`, windows.Principals(windows.SecretEntries, ""), true)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := windows.Exact(r, windows.SecretEntries); err != nil || !ok {
		t.Errorf("rules on the copy: %s: %v", sddl(t, c, dir+`\secret.conf`), err)
	}

	// A folder, a symlink or a junction on the way is refused, and the copy
	// is left as it was.
	target, targetDir := mklinks(t, c, dir)
	for name, bad := range map[string]string{
		"a folder":           targetDir,
		"a symlink":          dir + `\sym.txt`,
		"through a junction": dir + `\junction\inside.txt`,
	} {
		if err := windows.ApplyFileCopy(ctx, c, dest, bad, nil); err == nil {
			t.Errorf("%s: wasn't refused", name)
		} else {
			t.Logf("%s: %v", name, err)
		}
	}
	if got := strings.TrimSpace(fileText(t, c, dest)); got != b64(content) {
		t.Error("a refused copy changed the file")
	}
	if fileText(t, c, target) == fileText(t, c, dest) {
		t.Error("a link's target reached the copy")
	}
	noTemp(t, c, dir)
}

// A windows_file step with source_path copies a file already on the host,
// plans clean after, sees a hand edit of the copy and a change to the
// source, and names a source that's gone. An earlier step that rewrites the
// source while the copy's rules have drifted applies without OpenTofu's
// "inconsistent result" (#1377, #1376).
func TestFileSourcePathFlow(t *testing.T) {
	f := newFlow(t)
	c := connect(t)
	dir := tempDir(t, c)
	src, dest := dir+`\app.conf.sample`, dir+`\app.conf`
	read := func(p string) string {
		t.Helper()
		return strings.TrimSpace(run(t, c, `param($A) [IO.File]::ReadAllText($A.p)`, map[string]any{"p": p}).Text)
	}
	copyStep := fmt.Sprintf(`step "app_conf" {
    windows_file {
      path        = %q
      source_path = %q
      acl {
        principal = "S-1-5-32-544"
        rights    = ["FullControl"]
      }
      acl {
        principal = "S-1-5-18"
        rights    = ["FullControl"]
      }
    }
  }`, dest, src)
	steps := func(sample string) string {
		return fmt.Sprintf(`step "sample" {
    windows_file {
      path    = %q
      content = %q
    }
  }
  `, src, sample) + copyStep
	}

	f.cycle(steps("listen = 80"), func() {
		run(t, c, `param($A) [IO.File]::WriteAllText($A.p, 'listen = 8080')`, map[string]any{"p": dest})
	})
	if got := read(dest); got != "listen = 80" {
		t.Fatalf("after restoring the copy: %q", got)
	}

	// A change to the source made outside Conn3x shows in source_sha256.
	// The sample step puts it back first, and the copy follows in the same apply.
	run(t, c, `param($A) [IO.File]::WriteAllText($A.p, 'listen = 81')`, map[string]any{"p": src})
	if out := f.expect(2, "plan", "-detailed-exitcode"); !strings.Contains(out, "source_sha256") || strings.Contains(out, "listen = 81") {
		t.Fatalf("plan after a source change:\n%s", out)
	}
	f.expect(0, "apply", "-auto-approve")
	f.expect(0, "plan", "-detailed-exitcode")

	// The copy's rules drift by hand while the earlier step rewrites its
	// source: one apply copies the new source and puts the rules back.
	run(t, c, `param($A)
$s = Get-Acl -LiteralPath $A.p
$s.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-545'), 'Read', 'Allow')))
Set-Acl -LiteralPath $A.p -AclObject $s`, map[string]any{"p": dest})
	f.write(steps("listen = 82"))
	f.expect(0, "apply", "-auto-approve")
	if got := read(dest); got != "listen = 82" {
		t.Fatalf("after the earlier step rewrote the source: %q", got)
	}
	f.expect(0, "plan", "-detailed-exitcode")

	// With the sample step gone and its file removed, apply names the source
	// and leaves the copy alone.
	f.write(copyStep)
	run(t, c, `param($A) Remove-Item -LiteralPath $A.p`, map[string]any{"p": src})
	out, code := f.tool("apply", "-auto-approve", "-no-color", "-input=false")
	if code == 0 || !strings.Contains(out, "source_path "+src+" doesn't exist on the host") {
		t.Fatalf("apply with the source gone exited %d:\n%s", code, out)
	}
	if got := read(dest); got != "listen = 82" {
		t.Fatalf("a failed copy changed the file: %q", got)
	}
}
