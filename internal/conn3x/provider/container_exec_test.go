// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
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
		got := c.engine + " " + strings.Join(args, " ")
		if !strings.HasPrefix(got, tc.want+" ") || args[len(args)-2] != "conn3x" || !strings.HasSuffix(args[len(args)-1], "umask 022; id") {
			t.Errorf("%v: %q %q", tc.set, got, args[len(args)-1])
		}
	}
}

func TestExecTargetRefuses(t *testing.T) {
	for want, set := range map[string]map[string]cty.Value{
		"can't be set with container_engine = \"kubectl\"": {"container": cty.StringVal("p"), "container_engine": cty.StringVal("kubectl"), "user": cty.StringVal("root")},
		"go with container_engine = \"kubectl\"":           {"container": cty.StringVal("c"), "kube_namespace": cty.StringVal("x")},
		"not \"lxc\"":                                      {"container": cty.StringVal("c"), "container_engine": cty.StringVal("lxc")},
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
	if res, err := h.Run(context.Background(), "nope-not-a-command", nil); err != nil || res.ExitCode != 127 {
		t.Fatalf("a missing command in a running container: %v, exit %d", err, res.ExitCode)
	}
	if res, err := h.Run(context.Background(), "echo oops >&2; exit 255", nil); err != nil || res.ExitCode != 255 || string(res.Stderr) != "oops\n" {
		t.Fatalf("a command's own 255: %v, exit %d, stderr %q", err, res.ExitCode, res.Stderr)
	}
	// The engine fails, exiting 255 while the container runs: an error,
	// not a command's answer.
	typo, err := pooled(context.Background(), execBlock(map[string]cty.Value{"host": cty.StringVal("box"), "container": cty.StringVal(name), "user": cty.StringVal("nosuchuser")}), 0)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := typo.Run(context.Background(), "test -e /etc/passwd", nil); err == nil {
		t.Fatalf("a user that doesn't exist read as exit %d", res.ExitCode)
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

// kubectl's own errors exit 1, as a command can; without the shell's
// report they're the engine's failure. A stand-in kubectl shows it.
func TestExecEngineFailureWithoutReport(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "kubectl")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho 'Error from server (NotFound): pods \"web-0\" not found' >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	c, err := execTarget(execBlock(map[string]cty.Value{"container": cty.StringVal("web-0"), "container_engine": cty.StringVal("kubectl")}))
	if err != nil {
		t.Fatal(err)
	}
	if res, err := c.Run(context.Background(), "test -e /etc/passwd", nil); err == nil || !strings.Contains(err.Error(), "NotFound") {
		t.Fatalf("a missing pod gave exit %d, %v", res.ExitCode, err)
	}
}
