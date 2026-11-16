// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh/sshtest"
	"github.com/opentofu/opentofu/internal/providers"
)

// brRuntime stands in for podman or docker: each subcommand answers from
// fail, or as a container whose sshd is the sshtest server on port.
type brRuntime struct {
	mu      sync.Mutex
	port    string            // what "port" prints
	hostKey string            // what cat of the host key prints
	fail    map[string]string // a subcommand, or "exec <first arg>", that fails with this
	calls   [][]string
}

func brSwapCLI(t *testing.T, r *brRuntime) {
	t.Helper()
	old := containerCLI
	containerCLI = r.cli
	t.Cleanup(func() { containerCLI = old })
}

func (r *brRuntime) cli(_ context.Context, runtime string, args ...string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, append([]string{runtime}, args...))
	what := args[0]
	if what == "exec" {
		what += " " + args[2]
	}
	if msg, ok := r.fail[what]; ok {
		return "", errors.New(msg)
	}
	switch what {
	case "run":
		return "c0ffee\n", nil
	case "port":
		return r.port, nil
	case "exec cat":
		return r.hostKey, nil
	}
	return "", nil
}

func (r *brRuntime) ran(what string) [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out [][]string
	for _, c := range r.calls {
		if c[1] == what {
			out = append(out, c)
		}
	}
	return out
}

func brContainer(attrs map[string]cty.Value) cty.Value {
	vals := map[string]cty.Value{}
	for name, ty := range testContainerSchema().Block.ImpliedType().AttributeTypes() {
		vals[name] = cty.NullVal(ty)
	}
	for k, v := range attrs {
		vals[k] = v
	}
	return cty.ObjectVal(vals)
}

func TestTestContainerValidatesAndPlans(t *testing.T) {
	for want, attrs := range map[string]map[string]cty.Value{
		"":                         {"image": cty.StringVal("ghcr.io/conn3xorg/test-rocky10"), "runtime": cty.StringVal("podman")},
		"image must name an image": {"image": cty.StringVal("--privileged")},
		"runtime must be":          {"image": cty.StringVal("rocky"), "runtime": cty.StringVal("lxc")},
	} {
		d := validateTestContainer(brContainer(attrs))
		if (want == "") != !d.HasErrors() || (want != "" && !strings.Contains(d.Err().Error(), want)) {
			t.Errorf("%v: %v, want %q", attrs, d.Err(), want)
		}
	}
	if d := validateTestContainer(cty.NullVal(testContainerSchema().Block.ImpliedType())); d.HasErrors() {
		t.Error(d.Err())
	}

	cfg := brContainer(map[string]cty.Value{"image": cty.StringVal("rocky")})
	created := planTestContainer(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), ProposedNewState: cfg})
	if created.PlannedState.GetAttr("runtime").IsKnown() || created.PlannedState.GetAttr("port").IsKnown() || len(created.RequiresReplace) != 0 {
		t.Errorf("create: %#v, replace %v", created.PlannedState, created.RequiresReplace)
	}
	prior := brContainer(map[string]cty.Value{"image": cty.StringVal("rocky"), "runtime": cty.StringVal("docker"), "id": cty.StringVal("c0ffee")})
	// The same image keeps the container, with or without runtime set.
	for _, rt := range []cty.Value{cty.NullVal(cty.String), cty.StringVal("docker")} {
		same := brContainer(map[string]cty.Value{"image": cty.StringVal("rocky"), "runtime": rt})
		if plan := planTestContainer(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: same}); !plan.PlannedState.RawEquals(prior) {
			t.Errorf("runtime %#v: planned %#v", rt, plan.PlannedState)
		}
	}
	for name, next := range map[string]cty.Value{
		"another image":   brContainer(map[string]cty.Value{"image": cty.StringVal("debian"), "runtime": cty.StringVal("docker")}),
		"another runtime": brContainer(map[string]cty.Value{"image": cty.StringVal("rocky"), "runtime": cty.StringVal("podman")}),
	} {
		plan := planTestContainer(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: next})
		if len(plan.RequiresReplace) == 0 || plan.PlannedState.GetAttr("id").IsKnown() {
			t.Errorf("%s: %#v, replace %v", name, plan.PlannedState, plan.RequiresReplace)
		}
	}
	if plan := planTestContainer(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: cty.NullVal(prior.Type())}); !plan.PlannedState.IsNull() {
		t.Error("planned a removal as something")
	}
}

// Creating starts the container, gives root a key made for it, pins its
// host key and waits for its sshd; destroying removes it and the key.
func TestTestContainerLifecycle(t *testing.T) {
	s := sshtest.New(t)
	r := &brRuntime{port: fmt.Sprintf("0.0.0.0:%d\n[::]:%d\n", s.Port, s.Port), hostKey: "ssh-ed25519 AAAAC3Nza root@test\n"}
	brSwapCLI(t, r)
	planned := brContainer(map[string]cty.Value{"image": cty.StringVal("rocky"), "runtime": cty.StringVal("docker")})
	resp := applyTestContainer(ctx, providers.ApplyResourceChangeRequest{PriorState: cty.NullVal(planned.Type()), PlannedState: planned})
	if resp.Diagnostics.HasErrors() {
		t.Fatal(resp.Diagnostics.Err())
	}
	st := resp.NewState
	if port, _ := st.GetAttr("port").AsBigFloat().Int64(); st.GetAttr("id").AsString() != "c0ffee" || int(port) != s.Port || st.GetAttr("host_key").AsString() != "ssh-ed25519 AAAAC3Nza" {
		t.Errorf("state %#v", st)
	}
	run := r.ran("run")
	if len(run) != 1 || !slices.Contains(run[0], "--cgroupns=host") || run[0][len(run[0])-1] != "rocky" {
		t.Errorf("run %v", run)
	}
	kh, err := os.ReadFile(st.GetAttr("known_hosts_file").AsString())
	if want := fmt.Sprintf("[127.0.0.1]:%d ssh-ed25519 AAAAC3Nza\n", s.Port); err != nil || string(kh) != want {
		t.Errorf("known_hosts %q, %v, want %q", kh, err, want)
	}
	key := st.GetAttr("private_key_file").AsString()
	if b, err := os.ReadFile(key); err != nil || !strings.Contains(string(b), "OPENSSH PRIVATE KEY") {
		t.Errorf("key %q, %v", b, err)
	}

	// A refresh keeps it while inspect finds it, and drops it after.
	if read := readTestContainer(ctx, providers.ReadResourceRequest{PriorState: st}); !read.NewState.RawEquals(st) {
		t.Error("lost a container that's there")
	}
	r.fail = map[string]string{"container": "no such container"}
	if read := readTestContainer(ctx, providers.ReadResourceRequest{PriorState: st}); !read.NewState.IsNull() {
		t.Error("kept a container that's gone")
	}
	if read := readTestContainer(ctx, providers.ReadResourceRequest{PriorState: cty.NullVal(st.Type())}); !read.NewState.IsNull() {
		t.Error("read something from nothing")
	}

	r.fail = map[string]string{"rm": "permission denied"}
	if d := applyTestContainer(ctx, providers.ApplyResourceChangeRequest{PriorState: st, PlannedState: cty.NullVal(st.Type())}).Diagnostics; !d.HasErrors() {
		t.Error("destroyed a container rm refused")
	}
	r.fail = nil
	if d := applyTestContainer(ctx, providers.ApplyResourceChangeRequest{PriorState: st, PlannedState: cty.NullVal(st.Type())}).Diagnostics; d.HasErrors() {
		t.Fatal(d.Err())
	}
	if _, err := os.Stat(filepath.Dir(key)); !os.IsNotExist(err) {
		t.Errorf("the key's directory is still there: %v", err)
	}
}

// Each step that fails stops the create, and a container already started
// is removed again.
func TestTestContainerCreateFailures(t *testing.T) {
	s := sshtest.New(t)
	good := fmt.Sprintf("127.0.0.1:%d\n", s.Port)
	for want, r := range map[string]*brRuntime{
		"pull failed":             {fail: map[string]string{"run": "pull failed"}},
		"not an address and port": {port: "nothing\n"},
		`printed the port "ssh"`:  {port: "127.0.0.1:ssh\n"},
		"no ed25519 host key":     {port: good, fail: map[string]string{"exec cat": "no such file"}},
		"host key is empty":       {port: good, hostKey: "\n"},
		"read-only file system":   {port: good, fail: map[string]string{"exec sh": "read-only file system"}},
	} {
		brSwapCLI(t, r)
		planned := brContainer(map[string]cty.Value{"image": cty.StringVal("rocky"), "runtime": cty.StringVal("podman")})
		d := applyTestContainer(ctx, providers.ApplyResourceChangeRequest{PriorState: cty.NullVal(planned.Type()), PlannedState: planned}).Diagnostics
		if !d.HasErrors() || !strings.Contains(d.Err().Error(), want) {
			t.Errorf("%s: %v", want, d.Err())
			continue
		}
		if started := len(r.ran("run")) == 1 && r.fail["run"] == ""; started != (len(r.ran("rm")) == 1) {
			t.Errorf("%s: started %v, removed %v", want, started, r.ran("rm"))
		}
	}
}

// Without runtime, podman is the default when it's installed, then docker;
// with neither, the create says what's missing.
func TestTestContainerDefaultRuntime(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	if _, err := defaultRuntime(); err == nil || !strings.Contains(err.Error(), "neither is on the PATH") {
		t.Errorf("no runtime: %v", err)
	}
	planned := brContainer(map[string]cty.Value{"image": cty.StringVal("rocky")})
	if d := applyTestContainer(ctx, providers.ApplyResourceChangeRequest{PriorState: cty.NullVal(planned.Type()), PlannedState: planned}).Diagnostics; !d.HasErrors() {
		t.Error("created a container with no runtime")
	}
	// The real CLI says which runtime it couldn't find.
	if _, err := containerCLI(ctx, "docker", "ps"); err == nil || !strings.Contains(err.Error(), "needs docker") {
		t.Errorf("no docker: %v", err)
	}
	for _, rt := range []string{"docker", "podman"} {
		if err := os.WriteFile(filepath.Join(dir, rt), []byte("#!/bin/sh\nexit 3\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if got, err := defaultRuntime(); err != nil || got != rt {
			t.Errorf("with %s: %q, %v", rt, got, err)
		}
	}
	if _, err := containerCLI(ctx, "podman", "ps"); err == nil || !strings.Contains(err.Error(), "podman ps") {
		t.Errorf("a failing podman: %v", err)
	}
}

// waitForSSH gives up when the run stops.
func TestWaitForSSHStops(t *testing.T) {
	stopped, cancel := context.WithCancel(ctx)
	cancel()
	if err := waitForSSH(stopped, 1); !errors.Is(err, context.Canceled) {
		t.Errorf("got %v", err)
	}
}
