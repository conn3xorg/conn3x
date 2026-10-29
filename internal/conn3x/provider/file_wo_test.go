// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

var testHMACKey = strings.Repeat("k", 32)

func newWOTest(t *testing.T) *fileTest {
	t.Setenv("CONN3X_HMAC_KEY", testHMACKey)
	return newFileTest(t)
}

func (f *fileTest) createWO(secret string) (cty.Value, cty.Value) {
	cfg := f.config(map[string]cty.Value{"content_wo": cty.StringVal(secret)})
	null := cty.NullVal(cfg.Type())
	return f.apply(null, f.plan(null, cfg).PlannedState, cfg), cfg
}

func TestFileWriteOnlyKeepsSecretOutOfState(t *testing.T) {
	f := newWOTest(t)
	cfg := f.config(map[string]cty.Value{"content_wo": cty.StringVal("s3cret\n")})
	null := cty.NullVal(cfg.Type())
	planned := f.plan(null, cfg).PlannedState
	want := cty.StringVal(contentHMAC([]byte(testHMACKey), f.path, "s3cret\n"))
	for name, v := range map[string]cty.Value{"content": planned.GetAttr("content"), "sha256": planned.GetAttr("sha256"), "content_wo": planned.GetAttr("content_wo")} {
		if !v.IsNull() {
			t.Errorf("planned %s = %#v, want null", name, v)
		}
	}
	if got := planned.GetAttr("content_hmac"); !got.RawEquals(want) {
		t.Fatalf("planned content_hmac = %#v, want %#v", got, want)
	}

	state := f.apply(null, planned, cfg)
	if got, _ := os.ReadFile(f.path); string(got) != "s3cret\n" {
		t.Fatalf("host file = %q", got)
	}
	if strings.Contains(fmt.Sprintf("%#v", state), "s3cret") {
		t.Fatal("the secret reached state")
	}
	if got := state.GetAttr("content_hmac"); !got.RawEquals(want) {
		t.Fatalf("state content_hmac = %#v", got)
	}
}

func TestFileWriteOnlyNoChange(t *testing.T) {
	f := newWOTest(t)
	state, cfg := f.createWO("s3cret")
	read := f.read(state)
	if !read.RawEquals(state) {
		t.Fatalf("read changed state:\n%#v\nwant\n%#v", read, state)
	}
	if planned := f.plan(read, cfg).PlannedState; !planned.RawEquals(read) {
		t.Fatalf("no-op plan changed state:\n%#v", planned)
	}
}

func TestFileWriteOnlyDetectsDrift(t *testing.T) {
	f := newWOTest(t)
	state, cfg := f.createWO("s3cret")
	if err := os.WriteFile(f.path, []byte("hacked"), 0o644); err != nil {
		t.Fatal(err)
	}
	read := f.read(state)
	if read.GetAttr("content_hmac").RawEquals(state.GetAttr("content_hmac")) {
		t.Fatal("drift on the host not seen")
	}
	if !read.GetAttr("content").IsNull() {
		t.Fatal("read put content in state")
	}
	planned := f.plan(read, cfg).PlannedState
	if !planned.GetAttr("content_hmac").RawEquals(state.GetAttr("content_hmac")) {
		t.Fatal("drift not planned back")
	}
	f.apply(read, planned, cfg)
	if got, _ := os.ReadFile(f.path); string(got) != "s3cret" {
		t.Fatalf("apply left %q", got)
	}
}

func TestFileWriteOnlyUnknownContent(t *testing.T) {
	f := newWOTest(t)
	cfg := f.config(map[string]cty.Value{"content_wo": cty.UnknownVal(cty.String)})
	planned := f.plan(cty.NullVal(cfg.Type()), cfg).PlannedState
	if planned.GetAttr("content_hmac").IsKnown() {
		t.Fatal("content_hmac should be unknown when content_wo is")
	}
}

func TestFileSwitchToWriteOnlyAndBack(t *testing.T) {
	f := newWOTest(t)
	plain := f.create("plain", nil)
	woCfg := f.config(map[string]cty.Value{"content_wo": cty.StringVal("s3cret")})
	planned := f.plan(plain, woCfg).PlannedState
	if !planned.GetAttr("content").IsNull() || !planned.GetAttr("sha256").IsNull() || planned.GetAttr("content_hmac").IsNull() {
		t.Fatalf("switch to write-only planned %#v", planned)
	}
	if want := cty.StringVal(contentHMAC([]byte(testHMACKey), f.path, "s3cret")); !planned.GetAttr("content_hmac").RawEquals(want) {
		t.Fatalf("switch planned content_hmac %#v, want %#v", planned.GetAttr("content_hmac"), want)
	}
	wo := f.apply(plain, planned, woCfg)

	back := f.config(map[string]cty.Value{"content": cty.StringVal("plain")})
	planned = f.plan(wo, back).PlannedState
	if !planned.GetAttr("content_hmac").IsNull() || planned.GetAttr("content").AsString() != "plain" {
		t.Fatalf("switch back planned %#v", planned)
	}
}

func TestFileContentStateHasNoHMAC(t *testing.T) {
	f := newWOTest(t)
	if got := f.create("plain", nil).GetAttr("content_hmac"); !got.IsNull() {
		t.Fatalf("content_hmac = %#v, want null for plain content", got)
	}
}

func TestFileNeedsExactlyOneContent(t *testing.T) {
	f := newWOTest(t)
	for name, cfg := range map[string]cty.Value{
		"both":    f.config(map[string]cty.Value{"content": cty.StringVal("a"), "content_wo": cty.StringVal("b")}),
		"neither": f.config(nil),
	} {
		resp := f.p.ValidateResourceConfig(ctx, providers.ValidateResourceConfigRequest{TypeName: "conn3x_file", Config: cfg})
		if !resp.Diagnostics.HasErrors() {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestFileWriteOnlyOtherKey(t *testing.T) {
	f := newWOTest(t)
	state, _ := f.createWO("s3cret")
	t.Setenv("CONN3X_HMAC_KEY", strings.Repeat("z", 32))
	resp := f.p.ReadResource(ctx, providers.ReadResourceRequest{TypeName: "conn3x_file", PriorState: state})
	if !resp.Diagnostics.HasErrors() || !strings.Contains(resp.Diagnostics.Err().Error(), "CONN3X_HMAC_KEY") {
		t.Fatalf("want a key mismatch error, got %v", resp.Diagnostics.Err())
	}
}

func TestFileUpgradesStateFromBeforeWriteOnly(t *testing.T) {
	old := `{"id":"h:/etc/motd","path":"/etc/motd","content":"hi","mode":"0644","owner":null,"group":null,"on_remove":"forget","sha256":"x","ssh":null}`
	resp := upgradeFile(providers.UpgradeResourceStateRequest{TypeName: "conn3x_file", RawStateJSON: []byte(old)})
	if resp.Diagnostics.HasErrors() {
		t.Fatal(resp.Diagnostics.Err())
	}
	if got := resp.UpgradedState.GetAttr("content_hmac"); !got.IsNull() {
		t.Fatalf("content_hmac = %#v", got)
	}
}

func TestFileWriteOnlyDefaultsToPrivateMode(t *testing.T) {
	f := newWOTest(t)
	cfg := f.config(map[string]cty.Value{"content_wo": cty.StringVal("s3cret")})
	if got := f.plan(cty.NullVal(cfg.Type()), cfg).PlannedState.GetAttr("mode"); !got.RawEquals(cty.StringVal("0600")) {
		t.Fatalf("mode = %#v, want 0600 for write-only content", got)
	}
}

// Moving a secret from content to content_wo makes the file private, even
// though the file already exists at 0644.
func TestFileSwitchToWriteOnlyMakesModePrivate(t *testing.T) {
	f := newWOTest(t)
	plain := f.create("s3cret", nil)
	cfg := f.config(map[string]cty.Value{"content_wo": cty.StringVal("s3cret")})
	if got := f.plan(plain, cfg).PlannedState.GetAttr("mode"); !got.RawEquals(cty.StringVal("0600")) {
		t.Fatalf("mode = %#v, want 0600", got)
	}
}

func TestFileWriteOnlyApplyChecksPlannedKey(t *testing.T) {
	f := newWOTest(t)
	cfg := f.config(map[string]cty.Value{"content_wo": cty.StringVal("s3cret")})
	null := cty.NullVal(cfg.Type())
	planned := f.plan(null, cfg).PlannedState
	// The plan was made with one key; apply runs somewhere with another.
	t.Setenv("CONN3X_HMAC_KEY", strings.Repeat("z", 32))
	resp := f.p.ApplyResourceChange(ctx, providers.ApplyResourceChangeRequest{TypeName: "conn3x_file", PriorState: null, PlannedState: planned, Config: cfg})
	if !resp.Diagnostics.HasErrors() {
		t.Fatal("apply with a different key than the plan succeeded")
	}
	if _, err := os.Stat(f.path); !os.IsNotExist(err) {
		t.Fatal("apply wrote the file before noticing the key mismatch")
	}
}

func TestFileWriteOnlyReadDoesNotCreateKey(t *testing.T) {
	f := newWOTest(t)
	state, _ := f.createWO("s3cret")
	t.Setenv("CONN3X_HMAC_KEY", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	resp := f.p.ReadResource(ctx, providers.ReadResourceRequest{TypeName: "conn3x_file", PriorState: state})
	if !resp.Diagnostics.HasErrors() {
		t.Fatal("read without the key succeeded")
	}
	if path, _ := hmacKeyPath(); fileExists(path) {
		t.Fatal("read created a key file")
	}
}

func TestFileWriteOnlyWarnsWhenKeyFileIsReadableByOthers(t *testing.T) {
	f := newWOTest(t)
	t.Setenv("CONN3X_HMAC_KEY", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	hmacKeyWarningShown = ""
	if _, err := hmacKey(true); err != nil {
		t.Fatal(err)
	}
	path, _ := hmacKeyPath()
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := f.config(map[string]cty.Value{"content_wo": cty.StringVal("s3cret")})
	planned := f.plan(cty.NullVal(cfg.Type()), cfg)
	if planned.Diagnostics.HasErrors() {
		t.Fatal(planned.Diagnostics.Err())
	}
	if len(planned.Diagnostics) != 1 || planned.Diagnostics[0].Severity() != tfdiags.Warning {
		t.Fatalf("plan diagnostics = %#v, want one warning", planned.Diagnostics)
	}
	msg := planned.Diagnostics[0].Description().Summary
	for _, want := range []string{path, "readable by group or other users", "chmod 600 " + path} {
		if !strings.Contains(msg, want) {
			t.Errorf("warning %q doesn't mention %q", msg, want)
		}
	}

	hmacKeyWarningShown = ""
	state, _ := f.createWO("s3cret")
	hmacKeyWarningShown = ""
	read := f.p.ReadResource(ctx, providers.ReadResourceRequest{TypeName: "conn3x_file", PriorState: state})
	if read.Diagnostics.HasErrors() || len(read.Diagnostics) != 1 || read.Diagnostics[0].Severity() != tfdiags.Warning {
		t.Fatalf("read diagnostics = %#v, want one warning", read.Diagnostics)
	}
}

func TestFileWriteOnlyDoesNotWarnForPrivateKeyFile(t *testing.T) {
	f := newWOTest(t)
	t.Setenv("CONN3X_HMAC_KEY", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	hmacKeyWarningShown = ""
	if _, err := hmacKey(true); err != nil {
		t.Fatal(err)
	}

	cfg := f.config(map[string]cty.Value{"content_wo": cty.StringVal("s3cret")})
	planned := f.plan(cty.NullVal(cfg.Type()), cfg)
	if len(planned.Diagnostics) != 0 {
		t.Fatalf("plan diagnostics = %#v, want none", planned.Diagnostics)
	}
}

func TestFileWriteOnlyDoesNotWarnForEnvironmentKey(t *testing.T) {
	f := newWOTest(t)
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	hmacKeyWarningShown = ""
	path := filepath.Join(dir, "conn3x", "hmac.key")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("z", 32)), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := f.config(map[string]cty.Value{"content_wo": cty.StringVal("s3cret")})
	planned := f.plan(cty.NullVal(cfg.Type()), cfg)
	if len(planned.Diagnostics) != 0 {
		t.Fatalf("plan diagnostics = %#v, want none for CONN3X_HMAC_KEY", planned.Diagnostics)
	}
}
