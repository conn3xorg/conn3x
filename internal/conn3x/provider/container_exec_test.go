// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

func execBlock(set map[string]cty.Value) cty.Value {
	return cty.ObjectVal(withNulls(connectionBlock().Block.ImpliedType(), set))
}

func withNulls(ty cty.Type, set map[string]cty.Value) map[string]cty.Value {
	vals := map[string]cty.Value{}
	for name, at := range ty.AttributeTypes() {
		vals[name] = cty.NullVal(at)
	}
	for k, v := range set {
		vals[k] = v
	}
	return vals
}

// The engine's command line: podman and docker take a user, kubectl a
// namespace and context, and every command gets the SSH prelude.
func TestExecArgs(t *testing.T) {
	for _, tc := range []struct {
		set  map[string]cty.Value
		want string
	}{
		{map[string]cty.Value{"container": cty.StringVal("web")}, "podman exec -i web /bin/sh -c"},
		{map[string]cty.Value{"container": cty.StringVal("web"), "container_engine": cty.StringVal("docker"), "user": cty.StringVal("app")}, "docker exec -i --user app web /bin/sh -c"},
		{map[string]cty.Value{"container": cty.StringVal("web"), "user": cty.StringVal("app"), "become": cty.True}, "podman exec -i --user 0 web /bin/sh -c"},
		{map[string]cty.Value{"container": cty.StringVal("web-0"), "container_engine": cty.StringVal("kubectl"), "kube_namespace": cty.StringVal("shop"), "kube_context": cty.StringVal("prod")}, "kubectl --context prod exec -i -n shop web-0 -- /bin/sh -c"},
	} {
		c, err := execTarget(execBlock(tc.set))
		if err != nil {
			t.Fatal(err)
		}
		args := c.args("id")
		got := c.engine + " " + strings.Join(args[:len(args)-1], " ")
		if got != tc.want || !strings.HasSuffix(args[len(args)-1], "umask 022; id") {
			t.Errorf("%v: %q %q", tc.set, got, args[len(args)-1])
		}
	}
}

func TestExecTargetRefuses(t *testing.T) {
	for want, set := range map[string]map[string]cty.Value{
		"can't be set with container_engine = \"kubectl\"": {"container": cty.StringVal("p"), "container_engine": cty.StringVal("kubectl"), "user": cty.StringVal("root")},
		"go with container_engine = \"kubectl\"":           {"container": cty.StringVal("c"), "kube_namespace": cty.StringVal("x")},
		"not \"lxc\"":                                       {"container": cty.StringVal("c"), "container_engine": cty.StringVal("lxc")},
	} {
		if _, err := execTarget(execBlock(set)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v: %v, want %q", set, err, want)
		}
	}
}

// A real container through podman: stdin in, output and a non-zero exit
// back as a Result, and a stopped container an error.
func TestExecInPodman(t *testing.T) {
	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("no podman")
	}
	name := "conn3x-exec-test"
	_ = exec.Command("podman", "rm", "-f", name).Run()
	if out, err := exec.Command("podman", "run", "-d", "--name", name, "docker.io/library/alpine:3.24", "sleep", "300").CombinedOutput(); err != nil {
		t.Skipf("can't start a container: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("podman", "rm", "-f", name).Run() })

	h, err := pooled(context.Background(), execBlock(map[string]cty.Value{"host": cty.StringVal("box"), "container": cty.StringVal(name)}), 0)
	if err != nil {
		t.Fatal(err)
	}
	res, err := h.Run(context.Background(), "cat; echo; locale 2>/dev/null | head -n1; exit 3", []byte("from stdin"))
	if err != nil || res.ExitCode != 3 || !strings.HasPrefix(string(res.Stdout), "from stdin\n") {
		t.Fatalf("%v %d %q %q", err, res.ExitCode, res.Stdout, res.Stderr)
	}
	if !h.alive() {
		t.Error("a running container isn't alive")
	}
	if again, _ := pooled(context.Background(), execBlock(map[string]cty.Value{"host": cty.StringVal("box"), "container": cty.StringVal(name)}), 0); again != h {
		t.Error("the same container got a second connection")
	}
	_ = exec.Command("podman", "stop", "-t", "0", name).Run()
	if _, err := h.Run(context.Background(), "true", nil); err == nil || !strings.Contains(err.Error(), "podman exec "+name) {
		t.Errorf("a stopped container gave %v", err)
	}
}
