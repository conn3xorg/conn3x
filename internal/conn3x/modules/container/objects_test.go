// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package container

import (
	"context"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// objectEngine answers inspect with one reply, then another after a
// change, and records what ran.
type objectEngine struct {
	inspect, after string
	ran            []string
}

func (f *objectEngine) Run(_ context.Context, cmd string, _ []byte) (ssh.Result, error) {
	f.ran = append(f.ran, cmd)
	if strings.Contains(cmd, " inspect -- ") {
		return ssh.Result{Stdout: []byte(f.inspect)}, nil
	}
	if f.after != "" {
		f.inspect = f.after
	}
	return ssh.Result{}, nil
}

func TestImageRefAndValidate(t *testing.T) {
	for i, want := range map[Image]string{
		{Name: "docker.io/library/nginx"}:              "docker.io/library/nginx",
		{Name: "docker.io/library/nginx", Tag: "1.27"}: "docker.io/library/nginx:1.27",
		{Name: "registry:5000/app", Tag: "v1"}:         "registry:5000/app:v1",
		{Name: "nginx@sha256:abc"}:                     "nginx@sha256:abc",
		{Name: "docker.io/library/nginx:1.27"}:         "docker.io/library/nginx:1.27",
	} {
		if err := i.Validate(); err != nil || i.Ref() != want {
			t.Errorf("%+v: ref %q, %v", i, i.Ref(), err)
		}
	}
	for _, bad := range []Image{
		{Name: "nginx; rm -rf /"},
		{Name: "nginx:1.27", Tag: "1.28"},
		{Name: "nginx@sha256:abc", Tag: "1"},
		{Name: "nginx", Tag: "-x"},
		{Name: "nginx", Engine: "lxc"},
	} {
		if bad.Validate() == nil {
			t.Errorf("%+v should be refused", bad)
		}
	}
}

func TestImagePulledOnceAndRemoved(t *testing.T) {
	ctx := context.Background()
	img := Image{Name: "docker.io/library/busybox", Tag: "1.37"}
	f := &objectEngine{inspect: "podman\n[]\nmissing\n", after: "podman\n[{\"Id\":\"abc\"}]\n"}
	if err := ApplyImage(ctx, f, img); err != nil {
		t.Fatal(err)
	}
	if f.ran[1] != "'podman' pull -- 'docker.io/library/busybox:1.37' >/dev/null" {
		t.Errorf("pull = %q", f.ran[1])
	}
	a, err := ReadImage(ctx, f, img)
	if err != nil || !a.Exists || a.ID != "abc" || a.Engine != "podman" {
		t.Errorf("read = %+v, %v", a, err)
	}
	f.ran = nil
	if err := ApplyImage(ctx, f, img); err != nil || len(f.ran) != 1 {
		t.Errorf("an image that's there is kept: %v, ran %q", err, f.ran)
	}
	if err := DeleteImage(ctx, f, img); err != nil || f.ran[2] != "'podman' image rm -- 'docker.io/library/busybox:1.37' >/dev/null" {
		t.Errorf("delete: %v, ran %q", err, f.ran)
	}
	f = &objectEngine{inspect: "docker\n[]\nmissing\n"}
	if err := DeleteImage(ctx, f, img); err != nil || len(f.ran) != 1 {
		t.Errorf("nothing to remove: %v, ran %q", err, f.ran)
	}
	if err := ApplyImage(ctx, f, img); err == nil || !strings.Contains(err.Error(), "isn't on the host after the pull") {
		t.Errorf("a pull that leaves nothing: %v", err)
	}
}

// Docker and Podman print a network differently; both read the same.
const dockerNetwork = `docker
[{"Name":"app","Id":"f00","Driver":"bridge","IPAM":{"Driver":"default","Config":[{"Subnet":"10.89.0.0/24","Gateway":"10.89.0.1"}]}}]
`

const podmanNetwork = `podman
[{"name":"app","id":"f00","driver":"bridge","network_interface":"podman1","subnets":[{"subnet":"10.89.0.0/24","gateway":"10.89.0.1"}],"ipam_options":{"driver":"host-local"}}]
`

func TestReadNetworkBothEngines(t *testing.T) {
	ctx := context.Background()
	n := Network{Name: "app", Subnet: "10.89.0.0/24"}
	for engine, out := range map[string]string{"docker": dockerNetwork, "podman": podmanNetwork} {
		a, err := ReadNetwork(ctx, &objectEngine{inspect: out}, n)
		if err != nil || a.Engine != engine || !a.Exists || len(n.Differences(a)) != 0 {
			t.Errorf("%s: %+v, %v, differences %v", engine, a, err, n.Differences(a))
		}
	}
	// Docker finds a network by the start of its ID too.
	if a, _ := ReadNetwork(ctx, &objectEngine{inspect: dockerNetwork}, Network{Name: "f0"}); a.Exists {
		t.Error("a network found by its ID isn't the one named")
	}
	a, _ := ReadNetwork(ctx, &objectEngine{inspect: dockerNetwork}, n)
	got := strings.Join(Network{Name: "app", Driver: "macvlan", Subnet: "10.90.0.0/24"}.Differences(a), "; ")
	if got != "its driver is bridge; its subnets are 10.89.0.0/24" {
		t.Errorf("differences = %q", got)
	}
	if d := (Network{Name: "app"}).Differences(a); len(d) != 0 {
		t.Errorf("no subnet set, any is fine: %v", d)
	}
}

func TestApplyNetwork(t *testing.T) {
	ctx := context.Background()
	n := Network{Name: "app", Subnet: "10.89.0.0/24"}
	f := &objectEngine{inspect: "docker\n[]\nmissing\n", after: dockerNetwork}
	if err := ApplyNetwork(ctx, f, n); err != nil {
		t.Fatal(err)
	}
	if f.ran[1] != "'docker' 'network' 'create' '--driver' 'bridge' '--subnet' '10.89.0.0/24' '--' 'app' >/dev/null" {
		t.Errorf("create = %q", f.ran[1])
	}
	moved := strings.Replace(dockerNetwork, "10.89.0.0/24", "10.88.0.0/24", 1)
	f = &objectEngine{inspect: moved, after: dockerNetwork}
	if err := ApplyNetwork(ctx, f, n); err != nil || !strings.HasPrefix(f.ran[1], "'docker' network rm -- 'app' >/dev/null || exit 1\n") {
		t.Errorf("another subnet recreates it: %v, ran %q", err, f.ran)
	}
	f = &objectEngine{inspect: dockerNetwork}
	if err := DeleteNetwork(ctx, f, n); err != nil || f.ran[1] != "'docker' network rm -- 'app' >/dev/null" {
		t.Errorf("delete: %v, ran %q", err, f.ran)
	}
	for _, bad := range []Network{
		{Name: "app", Driver: "overlay"},
		{Name: "app", Subnet: "10.89.0.1/24"},
		{Name: "app", Subnet: "10.89.0.0"},
		{Name: "-app"},
	} {
		if bad.Validate() == nil {
			t.Errorf("%+v should be refused", bad)
		}
	}
}

func TestVolume(t *testing.T) {
	ctx := context.Background()
	v := Volume{Name: "data"}
	f := &objectEngine{inspect: "podman\n[]\nmissing\n", after: "podman\n[{\"Name\":\"data\",\"Driver\":\"local\",\"Mountpoint\":\"/var/lib/containers/storage/volumes/data/_data\"}]\n"}
	if err := ApplyVolume(ctx, f, v); err != nil {
		t.Fatal(err)
	}
	if f.ran[1] != "'podman' 'volume' 'create' '--driver' 'local' '--' 'data' >/dev/null" {
		t.Errorf("create = %q", f.ran[1])
	}
	f = &objectEngine{inspect: "docker\n[{\"Name\":\"data\",\"Driver\":\"rexray\"}]\n"}
	if err := ApplyVolume(ctx, f, v); err == nil || !strings.Contains(err.Error(), "has driver rexray") || len(f.ran) != 1 {
		t.Errorf("another driver isn't changed under the data: %v, ran %q", err, f.ran)
	}
	f = &objectEngine{inspect: "docker\n[{\"Name\":\"data\",\"Driver\":\"local\"}]\n"}
	if err := DeleteVolume(ctx, f, v); err != nil || f.ran[1] != "'docker' volume rm -- 'data' >/dev/null" {
		t.Errorf("delete: %v, ran %q", err, f.ran)
	}
	if (Volume{Name: "data", Driver: "a b"}).Validate() == nil {
		t.Error("a driver with a space should be refused")
	}
}

func TestContainerNetworks(t *testing.T) {
	c := web
	c.Networks = []string{"front", "back"}
	joined := strings.Replace(dockerInspect, `"Mounts"`, `"NetworkSettings":{"Networks":{"back":{},"front":{}}},"Mounts"`, 1)
	a, err := Read(context.Background(), &fakeEngine{inspect: joined}, c)
	if err != nil || !c.InSync(a) {
		t.Fatalf("on both: %v, differences %v", err, c.Differences(a))
	}
	a.Networks = []string{"front"}
	if got := strings.Join(c.Differences(a), ""); got != "its networks are front" {
		t.Errorf("differences = %q", got)
	}
	f := &fakeEngine{inspect: "docker\n[]\nmissing\n", after: joined}
	if err := Apply(context.Background(), f, c); err != nil {
		t.Fatal(err)
	}
	if run := f.ran[1]; !strings.Contains(run, "'--network' 'front'") || !strings.Contains(run, "\n'docker' network connect -- 'back' 'web' >/dev/null || exit 1") {
		t.Errorf("run = %s", run)
	}
	for _, bad := range [][]string{{"host"}, {"a", "a"}, {"x y"}} {
		c.Networks = bad
		if c.Validate() == nil {
			t.Errorf("networks %q should be refused", bad)
		}
	}
}
