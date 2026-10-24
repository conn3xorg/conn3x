// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package account

import (
	"context"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

type host struct {
	answers map[string]string
	ran     []string
}

func (h *host) Run(_ context.Context, cmd string, _ []byte) (ssh.Result, error) {
	h.ran = append(h.ran, cmd)
	for k, v := range h.answers {
		if strings.Contains(cmd, k) {
			if v == "" {
				return ssh.Result{ExitCode: 2}, nil
			}
			return ssh.Result{Stdout: []byte(v)}, nil
		}
	}
	return ssh.Result{}, nil
}

var ctx = context.Background()

func ptr[T any](v T) *T { return &v }

func TestReadUser(t *testing.T) {
	h := &host{answers: map[string]string{
		"getent passwd": "deploy:x:1001:1001:Deploy:/home/deploy:/bin/bash\n",
		"getent group":  "deploy:x:1001:\n",
		"id -Gn":        "deploy wheel docker\n",
	}}
	u, err := ReadUser(ctx, h, "deploy")
	if err != nil {
		t.Fatal(err)
	}
	if !u.Exists || u.UID != 1001 || u.Group != "deploy" || u.Home != "/home/deploy" || u.Shell != "/bin/bash" {
		t.Fatalf("got %+v", u)
	}
	if strings.Join(u.Groups, ",") != "docker,wheel" {
		t.Fatalf("groups = %v, want sorted supplementary groups", u.Groups)
	}
}

func TestReadMissingUser(t *testing.T) {
	u, err := ReadUser(ctx, &host{answers: map[string]string{"getent passwd": ""}}, "nobody2")
	if err != nil || u.Exists {
		t.Fatalf("got %+v, %v", u, err)
	}
}

func TestUserNeedsChangeOnlyForSetFields(t *testing.T) {
	actual := User{Exists: true, UID: 1001, Group: "deploy", Groups: []string{"wheel"}, Home: "/home/deploy", Shell: "/bin/bash"}
	if UserNeedsChange(UserSpec{Name: "deploy"}, actual) {
		t.Error("unset fields caused a change")
	}
	if !UserNeedsChange(UserSpec{Name: "deploy", Shell: ptr("/bin/zsh")}, actual) {
		t.Error("shell change not detected")
	}
	if !UserNeedsChange(UserSpec{Name: "deploy", Groups: &[]string{"wheel", "docker"}}, actual) {
		t.Error("groups change not detected")
	}
	if UserNeedsChange(UserSpec{Name: "deploy", Groups: &[]string{"wheel"}}, actual) {
		t.Error("equal groups reported as change")
	}
	if !UserNeedsChange(UserSpec{Name: "deploy"}, User{}) {
		t.Error("missing user not detected")
	}
}

func TestApplyUserCreate(t *testing.T) {
	h := &host{answers: map[string]string{"getent passwd": ""}}
	err := ApplyUser(ctx, h, UserSpec{Name: "deploy", UID: ptr(1500), Groups: &[]string{"wheel"}, Shell: ptr("/bin/bash"), System: true})
	if err != nil {
		t.Fatal(err)
	}
	last := h.ran[len(h.ran)-1]
	for _, want := range []string{"useradd", "-m", "-u 1500", "-G 'wheel'", "-s '/bin/bash'", "-r", "-- 'deploy'"} {
		if !strings.Contains(last, want) {
			t.Errorf("useradd missing %q: %s", want, last)
		}
	}
}

func TestApplyUserModify(t *testing.T) {
	h := &host{answers: map[string]string{
		"getent passwd": "deploy:x:1001:1001::/home/deploy:/bin/bash\n",
		"getent group":  "deploy:x:1001:\n",
		"id -Gn":        "deploy\n",
	}}
	if err := ApplyUser(ctx, h, UserSpec{Name: "deploy", Shell: ptr("/bin/zsh"), Groups: &[]string{}}); err != nil {
		t.Fatal(err)
	}
	last := h.ran[len(h.ran)-1]
	if !strings.Contains(last, "usermod") || !strings.Contains(last, "-s '/bin/zsh'") || !strings.Contains(last, "-G ''") {
		t.Fatalf("usermod: %s", last)
	}
}

func TestDeleteUserKeepsHome(t *testing.T) {
	h := &host{answers: map[string]string{"getent passwd": "deploy:x:1001:1001::/home/deploy:/bin/bash\n"}}
	if err := DeleteUser(ctx, h, "deploy"); err != nil {
		t.Fatal(err)
	}
	last := h.ran[len(h.ran)-1]
	if !strings.Contains(last, "userdel -- 'deploy'") || strings.Contains(last, "-r") {
		t.Fatalf("userdel: %s", last)
	}
}

func TestGroups(t *testing.T) {
	h := &host{answers: map[string]string{"getent group": "ops:x:2000:alice\n"}}
	g, err := ReadGroup(ctx, h, "ops")
	if err != nil || !g.Exists || g.GID != 2000 {
		t.Fatalf("got %+v, %v", g, err)
	}
	if GroupNeedsChange(GroupSpec{Name: "ops"}, g) || !GroupNeedsChange(GroupSpec{Name: "ops", GID: ptr(2001)}, g) {
		t.Fatal("group change detection wrong")
	}
	create := &host{answers: map[string]string{"getent group": ""}}
	if err := ApplyGroup(ctx, create, GroupSpec{Name: "ops", GID: ptr(2000), System: true}); err != nil {
		t.Fatal(err)
	}
	if last := create.ran[len(create.ran)-1]; !strings.Contains(last, "groupadd -g 2000 -r -- 'ops'") {
		t.Fatalf("groupadd: %s", last)
	}
}

func TestValidateNames(t *testing.T) {
	for _, bad := range []string{"", "Root", "a b", "x;rm", "-x", strings.Repeat("a", 33)} {
		if (UserSpec{Name: bad}).Validate() == nil {
			t.Errorf("user name %q accepted", bad)
		}
	}
	if err := (UserSpec{Name: "deploy-bot_1"}).Validate(); err != nil {
		t.Errorf("valid name rejected: %v", err)
	}
	if (UserSpec{Name: "x", Shell: ptr("bin/bash")}).Validate() == nil {
		t.Error("relative shell accepted")
	}
}
