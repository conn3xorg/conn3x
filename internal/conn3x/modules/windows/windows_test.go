// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// fake answers runs in order and records what each sent.
type fake struct {
	answers []map[string]any
	sent    []map[string]any
	err     error
}

func (f *fake) RunRaw(_ context.Context, _ string, stdin []byte) (ssh.Result, error) {
	raw, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(stdin)))
	var in map[string]any
	_ = json.Unmarshal(raw, &in)
	f.sent = append(f.sent, in)
	if f.err != nil {
		return ssh.Result{}, f.err
	}
	a := f.answers[0]
	f.answers = f.answers[1:]
	b, _ := json.Marshal(a)
	return ssh.Result{Stdout: []byte("conn3x-result:" + base64.StdEncoding.EncodeToString(b) + "\r\n")}, nil
}

func TestGather(t *testing.T) {
	value := map[string]any{
		"version": "10.0.26100", "build": "26100", "ubr": 2314, "product_type": 3, "arch": "AMD64", "cpus": 2, "memory_kb": 8 * 1024 * 1024,
		"ipv4": "10.0.0.4", "edition": "ServerDatacenter", "installation_type": "Server", "hostname": "web1", "domain": "WORKGROUP",
		"domain_role": 2, "powershell": "5.1.26100.1", "elevated": true,
	}
	f, err := Gather(context.Background(), &fake{answers: []map[string]any{{"ok": true, "value": value}}})
	if err != nil {
		t.Fatal(err)
	}
	if f.Arch != "x86_64" || f.Release != "2025" || f.MemoryMB != 8192 || f.Version != "10.0.26100" || f.Build != "26100" || f.UBR != 2314 || !f.Elevated {
		t.Errorf("got %+v", f)
	}
	value["product_type"] = 1
	if _, err := Gather(context.Background(), &fake{answers: []map[string]any{{"ok": true, "value": value}}}); err == nil || !strings.Contains(err.Error(), "client") {
		t.Errorf("client Windows: err = %v", err)
	}
}

func TestValidatePath(t *testing.T) {
	for _, ok := range []string{`C:\app`, `c:/app/x`, `C:\sp ace\[x]`} {
		if err := ValidatePath("p", ok); err != nil {
			t.Errorf("rejected %q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "app", `\app`, "/etc/passwd", `\\server`, `\\server\share\x`, `\\.\pipe\x`, `\\?\C:\x`, "C:\\a\nb", "C:\\a\x00", `C:\a|b`, `C:\*`, `C:\a"b`} {
		if ValidatePath("p", bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestWaitForValidate(t *testing.T) {
	for _, ok := range []WaitFor{{Path: `C:\x`}, {Service: "W3SVC"}, {Port: 9389}} {
		if err := ok.Validate(); err != nil {
			t.Errorf("rejected %+v: %v", ok, err)
		}
	}
	for _, bad := range []WaitFor{{}, {Path: `C:\x`, Port: 1}, {Service: "a';b"}, {Service: "$(x)'"}, {Port: 70000}, {Path: "/x"}} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

// A guard or wait reads the path at plan: a share or device would have the host
// contact something else just to answer.
func TestGuardsAndWaitsStayOnLocalDrives(t *testing.T) {
	for _, bad := range []string{`\\server\share\x`, `//server/share/x`, `\\.\pipe\x`, `\\?\C:\x`, `\\?\UNC\server\share`, `C:\a\CON`, `C:\a:stream`, `C:\a\..\b`} {
		if (Guards{Creates: bad}).Validate() == nil {
			t.Errorf("creates accepted %q", bad)
		}
		if (Guards{Creates: `C:\ok`, Removes: bad}).Validate() == nil {
			t.Errorf("removes accepted %q", bad)
		}
		if (WaitFor{Path: bad}).Validate() == nil {
			t.Errorf("wait accepted %q", bad)
		}
	}
	if err := (Guards{Creates: `C:\app\ready`, Removes: `c:/app/old`}).Validate(); err != nil {
		t.Error(err)
	}
	if err := (WaitFor{Path: `C:\app\ready`}).Validate(); err != nil {
		t.Error(err)
	}
}

func TestScrub(t *testing.T) {
	long := strings.Repeat("0123456789abcdef", 40)
	pem := "-----BEGIN KEY-----\nAAAAbase64line1\nBBBBbase64line2\n-----END KEY-----\n"
	wrapped := func(s string, width int, sep string) string {
		var b strings.Builder
		for len(s) > width {
			b.WriteString(s[:width] + sep)
			s = s[width:]
		}
		return b.String() + s
	}
	for name, tc := range map[string]struct{ text, secret, keep string }{
		"plain":             {"said hunter2.", "hunter2", "said "},
		"wrapped":           {"before " + wrapped(long, 80, "\r\n") + " after", long, "before "},
		"list continuation": {"Token : " + wrapped(long, 100, "\r\n        ") + "\r\nNext  : 1", long, "Next"},
		"pem with crlf":     {"x " + strings.ReplaceAll(pem, "\n", "\r\n") + "y", pem, "x "},
		"pem without ends":  {"x " + strings.TrimSpace(pem) + " y", pem, " y"},
		"crlf secret":       {"x " + pem, strings.ReplaceAll(pem, "\n", "\r\n"), "x "},
		"twice":             {"hunter2 and hun\nter2", "hunter2", " and "},
	} {
		got := Scrub(tc.text, []string{tc.secret})
		if !strings.Contains(got, "(sensitive value)") || !strings.Contains(got, tc.keep) {
			t.Errorf("%s: got %q", name, got)
		}
		flat := strings.NewReplacer("\r", "", "\n", "", " ", "").Replace(got)
		if strings.Contains(flat, strings.NewReplacer("\r", "", "\n", "", " ", "").Replace(tc.secret)) {
			t.Errorf("%s: still there: %q", name, got)
		}
	}
	if got := Scrub("a  b", []string{"   ", ""}); got != "a  b" {
		t.Errorf("a secret of spaces changed the text: %q", got)
	}
	if got := Scrub("x   y", []string{"   "}); got != "x(sensitive value)y" {
		t.Errorf("a secret of spaces wasn't blanked: %q", got)
	}
}

func TestSatisfiedUnless(t *testing.T) {
	ctx := context.Background()
	g := Guards{Unless: "Test-Path x"}
	for name, tc := range map[string]struct {
		answer map[string]any
		want   bool
	}{
		"true":          {map[string]any{"ok": true, "value": true}, true},
		"no output":     {map[string]any{"ok": true}, true},
		"false":         {map[string]any{"ok": true, "value": false}, false},
		"threw":         {map[string]any{"ok": false, "error": "nope"}, false},
		"native failed": {map[string]any{"ok": true, "rc": 2}, false},
	} {
		got, err := Satisfied(ctx, &fake{answers: []map[string]any{tc.answer}}, g, nil)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %v, %v", name, got, err)
		}
	}
	// A connection failure is not the check saying no.
	if _, err := Satisfied(ctx, &fake{err: errors.New("connection lost")}, g, nil); err == nil {
		t.Error("a failed run counted as the guard not holding")
	}
}

func TestSatisfiedChecksPathsBeforeUnless(t *testing.T) {
	f := &fake{answers: []map[string]any{{"ok": true, "value": false}}}
	ok, err := Satisfied(context.Background(), f, Guards{Creates: `C:\x`, Unless: "should not run"}, nil)
	if err != nil || ok || len(f.sent) != 1 {
		t.Fatalf("ok %v, err %v, runs %d", ok, err, len(f.sent))
	}
	if got := f.sent[0]["args"].(map[string]any)["creates"]; got != `C:\x` {
		t.Errorf("creates = %v", got)
	}
}

func TestRunScriptBlanksSecrets(t *testing.T) {
	f := &fake{answers: []map[string]any{{"ok": false, "error": "bad hunter2", "text": "said hunter2"}}}
	out, err := RunScript(context.Background(), f, "x", nil, []string{"hunter2"}, time.Minute)
	if err == nil || strings.Contains(err.Error(), "hunter2") || strings.Contains(out.Stdout, "hunter2") {
		t.Errorf("out %+v, err %v", out, err)
	}
}

func TestRunScriptFailsOnNativeExit(t *testing.T) {
	f := &fake{answers: []map[string]any{{"ok": true, "rc": 3010, "text": "output"}}}
	if _, err := RunScript(context.Background(), f, "x", nil, nil, time.Minute); err == nil || !strings.Contains(err.Error(), "3010") {
		t.Errorf("err = %v", err)
	}
}

func TestReadScriptsGoThroughRead(t *testing.T) {
	if _, err := ps.Read(context.Background(), &fake{}, script("apply_reboot.ps1"), nil); err == nil {
		t.Error("ps.Read ran an apply script")
	}
}

func TestFeatureInSyncWantsWhatWasAsked(t *testing.T) {
	ctx := context.Background()
	answer := func(installed bool, missing ...string) *fake {
		return &fake{answers: []map[string]any{{"ok": true, "value": map[string]any{"exists": true, "state": "Installed", "installed": installed, "missing": missing}}}}
	}
	for name, tc := range map[string]struct {
		f    Feature
		host *fake
		want bool
	}{
		"plain, installed":    {Feature{Name: "Web-Server"}, answer(true), true},
		"tools missing":       {Feature{Name: "Web-Server", ManagementTools: true}, answer(true, "Web-Mgmt-Console"), false},
		"sub-feature missing": {Feature{Name: "Web-Server", SubFeatures: true}, answer(true, "Web-Ftp-Server"), false},
		"all present":         {Feature{Name: "Web-Server", SubFeatures: true, ManagementTools: true}, answer(true), true},
	} {
		got, _, err := FeatureInSync(ctx, tc.host, tc.f)
		if err != nil || got != tc.want {
			t.Errorf("%s: %v, %v", name, got, err)
		}
		sent := tc.host.sent[0]["args"].(map[string]any)
		if sent["sub_features"] != tc.f.SubFeatures || sent["management_tools"] != tc.f.ManagementTools {
			t.Errorf("%s: sent %v", name, sent)
		}
	}
	// Removing asks nothing about its parts.
	f := &fake{answers: []map[string]any{{"ok": true, "value": map[string]any{"exists": true, "state": "Available"}}}}
	if got, _, err := FeatureInSync(ctx, f, Feature{Name: "X", Absent: true, SubFeatures: true}); err != nil || !got {
		t.Errorf("absent: %v, %v", got, err)
	}
	if f.sent[0]["args"].(map[string]any)["sub_features"] != false {
		t.Error("removal asked about sub-features")
	}
}
