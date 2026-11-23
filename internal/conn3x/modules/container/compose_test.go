// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package container

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

const (
	dockerPS = `{"Name":"app-web-1","Service":"web","State":"running","Labels":"com.docker.compose.service=web"}
{"Name":"app-worker-1","Service":"worker","State":"exited","Labels":"com.docker.compose.service=worker"}
`
	podmanPS = `[{"Names":["app_web_1"],"State":"running","Labels":{"com.docker.compose.service":"web"}},
 {"Names":["app_worker_1"],"State":"exited","Labels":{"com.docker.compose.service":"worker"}},
 {"Names":["app_old_1"],"State":"running","Labels":{"com.docker.compose.service":"old"}}]`
)

func TestParsePSBothEngines(t *testing.T) {
	for name, tc := range map[string]struct {
		out  string
		want map[string]bool
	}{
		"docker": {dockerPS, map[string]bool{"web": true, "worker": false}},
		"podman": {podmanPS, map[string]bool{"web": true, "worker": false, "old": true}},
		"none":   {"", map[string]bool{}},
		"empty":  {"[]", map[string]bool{}},
	} {
		got, err := parsePS(tc.out)
		if err != nil || len(got) != len(tc.want) {
			t.Errorf("%s: %v, %v", name, got, err)
		}
		for k, v := range tc.want {
			if got[k] != v {
				t.Errorf("%s: %s = %v", name, k, got[k])
			}
		}
	}
	if _, err := parsePS("{not json"); err == nil {
		t.Error("bad JSON should fail")
	}
}

func TestComposeDifferences(t *testing.T) {
	read := func(ps string) ComposeActual {
		a, err := parseCompose("podman\nh1\nok\nweb\nworker\n--ps--\n"+ps, "")
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	a := read(podmanPS)
	c := Compose{ProjectDir: "/opt/app"}
	if got := c.Differences(a, "h1"); !slices.Equal(got, []string{"service worker isn't running"}) {
		t.Errorf("present: %v", got)
	}
	if got := c.Differences(a, "h0"); len(got) != 2 || !strings.Contains(got[0], "files changed") {
		t.Errorf("changed files: %v", got)
	}
	c.RemoveOrphans = true
	if got := c.Differences(a, ""); len(got) != 2 || got[1] != "orphan service old has containers" {
		t.Errorf("orphans: %v", got)
	}
	c = Compose{ProjectDir: "/opt/app", Services: []string{"worker"}}
	if got := c.Differences(a, ""); !slices.Equal(got, []string{"service worker isn't running"}) {
		t.Errorf("services: %v", got)
	}
	c.State = "stopped"
	if got := c.Differences(a, ""); len(got) != 0 {
		t.Errorf("stopped worker: %v", got)
	}
	c.Services = nil
	if got := c.Differences(a, ""); !slices.Equal(got, []string{"service web is running"}) {
		t.Errorf("stopped: %v", got)
	}
	c = Compose{ProjectDir: "/opt/app", Services: []string{"nope"}}
	if got := c.Differences(a, ""); !slices.Equal(got, []string{"service nope isn't in its Compose files"}) {
		t.Errorf("unknown service: %v", got)
	}
	c = Compose{ProjectDir: "/opt/app", State: "absent"}
	if got := c.Differences(a, ""); len(got) != 1 {
		t.Errorf("absent with containers: %v", got)
	}
	if got := c.Differences(read(""), ""); len(got) != 0 {
		t.Errorf("absent, none left: %v", got)
	}
	nodir, _ := parseCompose("docker\nnodir\n", "")
	if got := (Compose{ProjectDir: "/x"}).Differences(nodir, "h"); !slices.Equal(got, []string{"its directory isn't there"}) {
		t.Errorf("no directory: %v", got)
	}
	bad, _ := parseCompose("docker\nh\nbad\n", "yaml: line 2: bad indent")
	if got := (Compose{ProjectDir: "/x"}).Differences(bad, "h"); !slices.Equal(got, []string{"compose config fails: yaml: line 2: bad indent"}) {
		t.Errorf("bad config: %v", got)
	}
}

func TestComposeValidate(t *testing.T) {
	good := Compose{ProjectDir: "/opt/app", ProjectName: "app_1", Files: []string{"compose.yaml"}, EnvFiles: []string{"/etc/app.env"}, Profiles: []string{"extra"}, Services: []string{"web"}, State: "stopped", Pull: "always", Content: "services: {}"}
	if err := good.Validate(); err != nil {
		t.Error(err)
	}
	for _, bad := range []Compose{
		{ProjectDir: "opt/app"},
		{ProjectDir: "/opt/app/"},
		{ProjectDir: "/opt/../app"},
		{ProjectDir: "/opt/app", ProjectName: "App"},
		{ProjectDir: "/opt/app", Files: []string{"-v"}},
		{ProjectDir: "/opt/app", EnvFiles: []string{"a\nb"}},
		{ProjectDir: "/opt/app", Profiles: []string{"a b"}},
		{ProjectDir: "/opt/app", Services: []string{"web;id"}},
		{ProjectDir: "/opt/app", State: "restarted"},
		{ProjectDir: "/opt/app", Pull: "if_not_present"},
		{ProjectDir: "/opt/app", Content: "x", Files: []string{"a.yaml", "b.yaml"}},
		{ProjectDir: "/opt/app", Engine: "lxc"},
	} {
		if bad.Validate() == nil {
			t.Errorf("%+v should be refused", bad)
		}
	}
}

// composeHost answers each read with the next of reads, and records the
// changes and what they read on stdin.
type composeHost struct {
	reads []string
	ran   []string
	stdin []string
}

func (f *composeHost) Run(_ context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	if strings.Contains(cmd, "config --services") {
		out := f.reads[0]
		if len(f.reads) > 1 {
			f.reads = f.reads[1:]
		}
		return ssh.Result{Stdout: []byte(out)}, nil
	}
	f.ran = append(f.ran, cmd)
	f.stdin = append(f.stdin, string(stdin))
	return ssh.Result{}, nil
}

func TestApplyComposeCommands(t *testing.T) {
	ctx := context.Background()
	down := "docker\nh0\nok\nweb\n--ps--\n"
	up := down + `{"Service":"web","State":"running"}` + "\n"

	c := Compose{ProjectDir: "/opt/my app", ProjectName: "app", Files: []string{"compose.yaml"}, Pull: "always", RemoveOrphans: true, Wait: true, Content: "services:\n  web: {image: x}\n"}
	f := &composeHost{reads: []string{down, up}}
	hash, err := ApplyCompose(ctx, f, c)
	if err != nil || hash != "h0" || len(f.ran) != 1 {
		t.Fatalf("hash %q, ran %v, %v", hash, f.ran, err)
	}
	for _, want := range []string{
		`mkdir -p -- '/opt/my app' && (umask 077 && cat > '/opt/my app/compose.yaml')`,
		`c() { docker compose '-p' 'app' '-f' 'compose.yaml' "$@"; }`,
		`c 'up' '-d' '--quiet-pull' '--pull' 'always' '--wait' '--remove-orphans' '--'`,
	} {
		if !strings.Contains(f.ran[0], want) {
			t.Errorf("missing %s in:\n%s", want, f.ran[0])
		}
	}
	if f.stdin[0] != c.Content {
		t.Errorf("content on stdin = %q", f.stdin[0])
	}

	// Still down after the up: the apply says so.
	f = &composeHost{reads: []string{down}}
	if _, err := ApplyCompose(ctx, f, Compose{ProjectDir: "/opt/app"}); err == nil || !strings.Contains(err.Error(), "service web isn't running") {
		t.Errorf("want a failure naming web, got %v", err)
	}

	f = &composeHost{reads: []string{strings.Replace(up, "docker", "podman", 1), strings.Replace(down, "docker", "podman", 1)}}
	if _, err := ApplyCompose(ctx, f, Compose{ProjectDir: "/opt/app", State: "stopped", Pull: "always", Services: []string{"web"}}); err != nil {
		t.Fatal(err)
	}
	if want := "c 'up' '-d' '--no-start' '--pull-always' '--' 'web' >/dev/null || exit 1\nc 'stop' '--' 'web'"; !strings.Contains(f.ran[0], want) {
		t.Errorf("stopped on podman, missing %q in:\n%s", want, f.ran[0])
	}

	for _, c := range []Compose{
		{ProjectDir: "/opt/app", Pull: "never"},
		{ProjectDir: "/opt/app", Wait: true},
		{ProjectDir: "/opt/app", EnvFiles: []string{"a", "b"}},
	} {
		f = &composeHost{reads: []string{strings.Replace(up, "docker", "podman", 1)}}
		if _, err := ApplyCompose(ctx, f, c); err == nil || !strings.Contains(err.Error(), "podman-compose") || len(f.ran) != 0 {
			t.Errorf("%+v on podman: ran %v, %v", c, f.ran, err)
		}
	}

	f = &composeHost{reads: []string{up, down}}
	if err := DeleteCompose(ctx, f, Compose{ProjectDir: "/opt/app", Content: "kept", RemoveOrphans: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.ran[0], "c 'down' '--remove-orphans' '--' >/dev/null") || strings.Contains(f.ran[0], "--volumes") || strings.Contains(f.ran[0], "cat >") {
		t.Errorf("delete ran:\n%s", f.ran[0])
	}
	f = &composeHost{reads: []string{"docker\nnodir\n"}}
	if err := DeleteCompose(ctx, f, Compose{ProjectDir: "/opt/app"}); err != nil || len(f.ran) != 0 {
		t.Errorf("no directory, nothing to take down: ran %v, %v", f.ran, err)
	}
}
