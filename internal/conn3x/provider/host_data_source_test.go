// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
	"github.com/opentofu/opentofu/internal/providers"
)

func TestHostDataSourceIsServed(t *testing.T) {
	p := &Provider{}
	schema, ok := p.GetProviderSchema(context.Background()).DataSources["conn3x_host"]
	if !ok {
		t.Fatal("conn3x_host is not in the schema")
	}
	for _, attr := range []string{"os_family", "os_id", "os_version", "arch", "cpus", "memory_mb", "ipv4"} {
		if a := schema.Block.Attributes[attr]; a == nil || !a.Computed {
			t.Errorf("%s is missing or not computed", attr)
		}
	}
	resp := p.ReadDataSource(context.Background(), providers.ReadDataSourceRequest{TypeName: "conn3x_nope", Config: cty.EmptyObjectVal})
	if !resp.Diagnostics.HasErrors() {
		t.Error("read an unknown data source")
	}
}

type posixFail struct{ err error }

func (p posixFail) Run(context.Context, string, []byte) (ssh.Result, error) {
	if p.err != nil {
		return ssh.Result{}, p.err
	}
	return ssh.Result{ExitCode: 1, Stderr: []byte("no os-release")}, nil
}

type rawAnswer struct {
	res  ssh.Result
	runs int
}

func (r *rawAnswer) RunRaw(context.Context, string, []byte) (ssh.Result, error) {
	r.runs++
	return r.res, nil
}

func windowsAnswer(productType int) *rawAnswer {
	b, _ := json.Marshal(map[string]any{"ok": true, "value": map[string]any{
		"version": "10.0.26100", "build": "26100", "ubr": 2314, "product_type": productType, "arch": "AMD64", "cpus": 2, "memory_kb": 8388608,
		"ipv4": "10.0.0.4", "edition": "ServerDatacenter", "installation_type": "Server", "hostname": "web1", "domain": "WORKGROUP",
		"domain_role": 2, "powershell": "5.1", "elevated": true,
	}})
	return &rawAnswer{res: ssh.Result{Stdout: []byte("conn3x-result:" + base64.StdEncoding.EncodeToString(b))}}
}

// The trap: circuits treat anything not Debian as Red Hat, so facts must never
// reach a circuit that didn't ask for Windows.
func TestWindowsFactsOnlyWhenAllowed(t *testing.T) {
	ctx := context.Background()
	refused := posixFail{ssh.ErrWindowsHost}
	if _, _, err := gatherFacts(ctx, refused, windowsAnswer(3), false); err == nil || !strings.Contains(err.Error(), "allow_windows") {
		t.Fatalf("without allow_windows: err = %v", err)
	}
	f, win, err := gatherFacts(ctx, refused, windowsAnswer(3), true)
	if err != nil {
		t.Fatal(err)
	}
	if f.Family != "windows" || f.ID != "windows" || f.Arch != "x86_64" || win.GetAttr("release").AsString() != "2025" ||
		win.GetAttr("build").AsString() != "26100" || !win.GetAttr("update_revision").RawEquals(cty.NumberIntVal(2314)) {
		t.Errorf("facts %+v, windows %#v", f, win)
	}
	if _, _, err := gatherFacts(ctx, refused, windowsAnswer(1), true); err == nil || !strings.Contains(err.Error(), "client") {
		t.Errorf("client Windows: err = %v", err)
	}
}

type posixOK struct{}

func (posixOK) Run(context.Context, string, []byte) (ssh.Result, error) {
	return ssh.Result{Stdout: []byte("id=rocky\nversion=10\nlike=rhel\narch=x86_64\ncpus=2\nmemory_kb=2048\nipv4=10.0.0.1\n")}, nil
}

// Linux sees no new round trip, and keeps its own error when the script fails.
func TestLinuxFactsDontTouchPowerShell(t *testing.T) {
	ctx := context.Background()
	raw := windowsAnswer(3)
	f, win, err := gatherFacts(ctx, posixOK{}, raw, false)
	if err != nil || f.Family != "redhat" || !win.IsNull() || raw.runs != 0 {
		t.Fatalf("facts %+v, windows %#v, err %v, PowerShell runs %d", f, win, err, raw.runs)
	}
	notFound := &rawAnswer{res: ssh.Result{ExitCode: 127, Stderr: []byte("sh: powershell.exe: not found")}}
	_, _, err = gatherFacts(ctx, posixFail{}, notFound, true)
	if err == nil || !strings.Contains(err.Error(), "no os-release") || notFound.runs != 1 {
		t.Fatalf("err = %v, PowerShell runs %d", err, notFound.runs)
	}
	boom := errors.New("gone")
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	unused := windowsAnswer(3)
	if _, _, err := gatherFacts(cancelled, posixFail{boom}, unused, true); !errors.Is(err, boom) || unused.runs != 0 {
		t.Errorf("after cancel: err = %v, runs %d", err, unused.runs)
	}
}
