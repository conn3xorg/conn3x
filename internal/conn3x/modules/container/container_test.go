// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package container

import (
	"context"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

func TestNormalImage(t *testing.T) {
	for in, want := range map[string]string{
		"nginx":                            "docker.io/library/nginx:latest",
		"nginx:1.27":                       "docker.io/library/nginx:1.27",
		"bitnami/redis:7":                  "docker.io/bitnami/redis:7",
		"docker.io/library/nginx:1.27":     "docker.io/library/nginx:1.27",
		"quay.io/prometheus/node-exporter": "quay.io/prometheus/node-exporter:latest",
		"localhost/app":                    "localhost/app:latest",
		"registry:5000/team/app":           "registry:5000/team/app:latest",
		"nginx@sha256:abc":                 "docker.io/library/nginx@sha256:abc",
		"ghcr.io/org/app:v1@sha256:abc":    "ghcr.io/org/app:v1@sha256:abc",
	} {
		if got := normalImage(in); got != want {
			t.Errorf("normalImage(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidate(t *testing.T) {
	ok := Container{Name: "web", Image: "nginx:1.27", Ports: []string{"8080:80", "127.0.0.1:8443:443/tcp", "[::1]:53:53/udp"}, Volumes: []string{"/srv/web:/usr/share/nginx/html:ro", "data:/var/lib/data", "/srv/x:/x:ro,Z"}, Env: map[string]string{"TZ": "UTC"}, Restart: "unless-stopped"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Container{
		{Name: "-web", Image: "nginx"},
		{Name: "web", Image: "nginx; rm -rf /"},
		{Name: "web", Image: "nginx", Ports: []string{"80"}},
		{Name: "web", Image: "nginx", Volumes: []string{"./rel:/x"}},
		{Name: "web", Image: "nginx", Volumes: []string{"/a:/b:bogus"}},
		{Name: "web", Image: "nginx", Env: map[string]string{"1X": "y"}},
		{Name: "web", Image: "nginx", Env: map[string]string{"X": "a\nY=b"}},
		{Name: "web", Image: "nginx", Restart: "sometimes"},
		{Name: "web", Image: "nginx", Engine: "lxc"},
	} {
		if bad.Validate() == nil {
			t.Errorf("%+v should be refused", bad)
		}
	}
}

// Docker keeps the image as written and no address; Podman writes the full
// reference and 0.0.0.0. Both mean the same container.
const dockerInspect = `docker
[{"Config":{"Image":"nginx:1.27","Env":["TZ=UTC","PATH=/usr/bin","NGINX_VERSION=1.27"],"Cmd":["nginx","-g","daemon off;"]},
  "State":{"Running":true},
  "HostConfig":{"PortBindings":{"80/tcp":[{"HostIp":"","HostPort":"8080"}]},"RestartPolicy":{"Name":"unless-stopped"}},
  "Mounts":[{"Type":"bind","Source":"/srv/web","Destination":"/usr/share/nginx/html","RW":false},{"Type":"volume","Name":"data","Source":"/var/lib/docker/volumes/data/_data","Destination":"/data","RW":true}]}]
`

const podmanInspect = `podman
[{"Config":{"Image":"docker.io/library/nginx:1.27","Env":["TZ=UTC"],"Cmd":["nginx","-g","daemon off;"]},
  "State":{"Running":true},
  "HostConfig":{"PortBindings":{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"8080"}]},"RestartPolicy":{"Name":"unless-stopped"}},
  "Mounts":[{"Type":"bind","Source":"/srv/web","Destination":"/usr/share/nginx/html","RW":false},{"Type":"volume","Name":"data","Source":"/var/lib/containers/storage/volumes/data/_data","Destination":"/data","RW":true}]}]
`

// fakeEngine answers inspect with one reply, then another after a run, and
// records what ran.
type fakeEngine struct {
	inspect, after string
	ran            []string
	stdin          []byte
}

func (f *fakeEngine) Run(_ context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	f.ran = append(f.ran, cmd)
	if strings.Contains(cmd, "container inspect") {
		return ssh.Result{Stdout: []byte(f.inspect)}, nil
	}
	f.stdin = stdin
	if f.after != "" {
		f.inspect = f.after
	}
	return ssh.Result{}, nil
}

var web = Container{Name: "web", Image: "nginx:1.27", Ports: []string{"8080:80"}, Volumes: []string{"/srv/web:/usr/share/nginx/html:ro", "data:/data"}, Env: map[string]string{"TZ": "UTC"}, Restart: "unless-stopped"}

func TestReadBothEngines(t *testing.T) {
	for engine, out := range map[string]string{"docker": dockerInspect, "podman": podmanInspect} {
		a, err := Read(context.Background(), &fakeEngine{inspect: out}, web)
		if err != nil {
			t.Fatal(err)
		}
		if a.Engine != engine || !web.InSync(a) {
			t.Errorf("%s: in sync = %v, differences %v", engine, web.InSync(a), web.Differences(a))
		}
	}
	a, err := Read(context.Background(), &fakeEngine{inspect: "docker\n[]\nmissing\n"}, web)
	if err != nil || a.Exists || web.InSync(a) {
		t.Errorf("missing: %+v, %v", a, err)
	}
}

func TestDifferences(t *testing.T) {
	a, _ := Read(context.Background(), &fakeEngine{inspect: dockerInspect}, web)
	changed := web
	changed.Image = "nginx:1.28"
	changed.Env = map[string]string{"TZ": "Europe/London"}
	changed.Ports = []string{"9090:80"}
	changed.Restart = "always"
	got := strings.Join(changed.Differences(a), "; ")
	for _, want := range []string{"its image is nginx:1.27", "its ports differ", "its env differs", "its restart policy is unless-stopped"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	a.Running = false
	if web.InSync(a) || len(web.Differences(a)) != 0 {
		t.Error("a stopped container is out of sync, with nothing else different")
	}
}

func TestApplyRecreatesWithEnvOnStdin(t *testing.T) {
	f := &fakeEngine{inspect: "docker\n[]\nmissing\n", after: dockerInspect}
	if err := Apply(context.Background(), f, web); err != nil {
		t.Fatal(err)
	}
	run := f.ran[1]
	if !strings.Contains(run, "'docker' 'run' '-d' '--name' 'web' '--restart' 'unless-stopped' '-p' '8080:80'") || !strings.Contains(run, "'--env-file' '/dev/stdin'") || strings.Contains(run, "UTC") {
		t.Errorf("run = %s", run)
	}
	if string(f.stdin) != "TZ=UTC\n" {
		t.Errorf("stdin = %q", f.stdin)
	}
	if strings.Contains(run, "rm -f") {
		t.Error("nothing to remove when it didn't exist")
	}

	old := strings.Replace(dockerInspect, `"nginx:1.27"`, `"nginx:1.26"`, 1)
	f = &fakeEngine{inspect: old, after: dockerInspect}
	if err := Apply(context.Background(), f, web); err != nil || !strings.Contains(f.ran[1], "'docker' rm -f -- 'web'") {
		t.Fatalf("a new image should recreate: %v, ran %q", err, f.ran)
	}

	stopped := strings.Replace(dockerInspect, `"Running":true`, `"Running":false`, 1)
	f = &fakeEngine{inspect: stopped, after: dockerInspect}
	if err := Apply(context.Background(), f, web); err != nil || f.ran[1] != "'docker' start -- 'web'" {
		t.Fatalf("a stopped container should only start: %v, ran %q", err, f.ran)
	}
}

func TestPodmanRestartService(t *testing.T) {
	f := &fakeEngine{inspect: "podman\n[]\nmissing\n", after: podmanInspect}
	if err := Apply(context.Background(), f, web); err != nil || !strings.Contains(f.ran[1], "podman-restart.service") {
		t.Fatalf("%v, ran %q", err, f.ran)
	}
}
