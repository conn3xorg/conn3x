// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package account

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// script answers each command with the first result whose key it holds,
// and loses the connection on a command holding lose.
type script struct {
	answers map[string]ssh.Result
	lose    string
	ran     []string
}

var errLost = errors.New("connection lost")

func (s *script) Run(_ context.Context, cmd string, _ []byte) (ssh.Result, error) {
	s.ran = append(s.ran, cmd)
	if s.lose != "" && strings.Contains(cmd, s.lose) {
		return ssh.Result{}, errLost
	}
	for k, v := range s.answers {
		if strings.Contains(cmd, k) {
			return v, nil
		}
	}
	return ssh.Result{}, nil
}

func out(s string) ssh.Result { return ssh.Result{Stdout: []byte(s)} }

var deploy = map[string]ssh.Result{
	"getent passwd": out("deploy:x:1001:1001:Deploy:/home/deploy:/bin/bash\n"),
	"getent group":  out("deploy:x:1001:\n"),
	"id -Gn":        out("deploy wheel\n"),
}

func TestValidateRefuses(t *testing.T) {
	for want, s := range map[string]UserSpec{
		`group name "Bad"`:         {Name: "deploy", Group: ptr("Bad")},
		`group name "x y"`:         {Name: "deploy", Groups: &[]string{"wheel", "x y"}},
		"must be an absolute path": {Name: "deploy", Shell: ptr("bash")},
		"uid must not be negative": {Name: "deploy", UID: ptr(-1)},
		`user name "Deploy"`:       {Name: "Deploy"},
	} {
		if err := s.Validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%+v: %v, want %q", s, err, want)
		}
	}
	for _, g := range []GroupSpec{{Name: "Bad"}, {Name: "ok", GID: ptr(-5)}} {
		if g.Validate() == nil {
			t.Errorf("%+v passed", g)
		}
	}
	if _, err := ReadUser(ctx, &script{}, "Bad"); err == nil {
		t.Error("read a bad user name")
	}
	if _, err := ReadGroup(ctx, &script{}, "Bad"); err == nil {
		t.Error("read a bad group name")
	}
}

func TestReadFailures(t *testing.T) {
	for _, lose := range []string{"getent passwd", "getent group", "id -Gn"} {
		if _, err := ReadUser(ctx, &script{answers: deploy, lose: lose}, "deploy"); !errors.Is(err, errLost) {
			t.Errorf("losing %s: %v", lose, err)
		}
	}
	s := &script{answers: map[string]ssh.Result{"getent passwd": {ExitCode: 1, Stderr: []byte("nss down\n")}}}
	if _, err := ReadUser(ctx, s, "deploy"); err == nil || err.Error() != "getent passwd deploy: nss down" {
		t.Errorf("getent fails: %v", err)
	}
	s = &script{answers: map[string]ssh.Result{"getent passwd": out("deploy:x:1001\n")}}
	if _, err := ReadUser(ctx, s, "deploy"); err == nil || !strings.Contains(err.Error(), "unexpected output") {
		t.Errorf("short passwd line: %v", err)
	}
	// A primary gid with no group name stays a number.
	s = &script{answers: map[string]ssh.Result{"getent passwd": out("deploy:x:1001:4242::/h:/bin/sh\n"), "getent group": {ExitCode: 2}, "id -Gn": out("4242\n")}}
	if u, err := ReadUser(ctx, s, "deploy"); err != nil || u.Group != "4242" || len(u.Groups) != 0 {
		t.Errorf("nameless gid: %+v, %v", u, err)
	}

	if _, err := ReadGroup(ctx, &script{lose: "getent"}, "app"); !errors.Is(err, errLost) {
		t.Errorf("group lost: %v", err)
	}
	s = &script{answers: map[string]ssh.Result{"getent group": {ExitCode: 1, Stderr: []byte("nss down")}}}
	if _, err := ReadGroup(ctx, s, "app"); err == nil || err.Error() != "getent group app: nss down" {
		t.Errorf("group getent fails: %v", err)
	}
	s = &script{answers: map[string]ssh.Result{"getent group": out("app:x\n")}}
	if _, err := ReadGroup(ctx, s, "app"); err == nil || !strings.Contains(err.Error(), "unexpected output") {
		t.Errorf("short group line: %v", err)
	}
}

func TestApplyUserChanges(t *testing.T) {
	// In sync: nothing beyond the reads.
	s := &script{answers: deploy}
	if err := ApplyUser(ctx, s, UserSpec{Name: "deploy", Group: ptr("deploy"), Home: ptr("/home/deploy"), Groups: &[]string{"wheel", "wheel"}}); err != nil || len(s.ran) != 3 {
		t.Errorf("in sync: %v, ran %q", err, s.ran)
	}
	s = &script{answers: deploy}
	if err := ApplyUser(ctx, s, UserSpec{Name: "deploy", UID: ptr(1002), Group: ptr("ops"), Home: ptr("/srv/deploy")}); err != nil {
		t.Fatal(err)
	}
	if got := s.ran[len(s.ran)-1]; got != "usermod -u 1002 -g 'ops' -d '/srv/deploy' -- 'deploy'" {
		t.Errorf("usermod: %s", got)
	}
	for name, spec := range map[string]UserSpec{
		"uid":    {Name: "deploy", UID: ptr(1)},
		"group":  {Name: "deploy", Group: ptr("x")},
		"home":   {Name: "deploy", Home: ptr("/x")},
		"shell":  {Name: "deploy", Shell: ptr("/bin/zsh")},
		"groups": {Name: "deploy", Groups: &[]string{}},
	} {
		u, _ := ReadUser(ctx, &script{answers: deploy}, "deploy")
		if !UserNeedsChange(spec, u) {
			t.Errorf("%s: no change needed", name)
		}
	}
	s = &script{answers: map[string]ssh.Result{"getent passwd": {ExitCode: 2}, "useradd": {ExitCode: 9}}}
	if err := ApplyUser(ctx, s, UserSpec{Name: "app"}); err == nil || err.Error() != "useradd: exit status 9" {
		t.Errorf("useradd fails silently: %v", err)
	}
	if got := s.ran[len(s.ran)-1]; got != "useradd -m -- 'app'" {
		t.Errorf("useradd: %s", got)
	}
	if err := ApplyUser(ctx, &script{lose: "getent"}, UserSpec{Name: "app"}); !errors.Is(err, errLost) {
		t.Errorf("read lost: %v", err)
	}
	if err := ApplyUser(ctx, &script{}, UserSpec{Name: "Bad"}); err == nil {
		t.Error("applied a bad name")
	}
	if err := ApplyUser(ctx, &script{answers: deploy, lose: "usermod"}, UserSpec{Name: "deploy", UID: ptr(5)}); !errors.Is(err, errLost) {
		t.Errorf("usermod lost: %v", err)
	}
}

func TestDeleteAndGroups(t *testing.T) {
	s := &script{answers: deploy}
	if err := DeleteUser(ctx, s, "deploy"); err != nil || s.ran[len(s.ran)-1] != "userdel -- 'deploy'" {
		t.Errorf("delete: %v, ran %q", err, s.ran)
	}
	s = &script{answers: map[string]ssh.Result{"getent passwd": {ExitCode: 2}}}
	if err := DeleteUser(ctx, s, "gone"); err != nil || len(s.ran) != 1 {
		t.Errorf("delete missing: %v, ran %q", err, s.ran)
	}

	app := map[string]ssh.Result{"getent group": out("app:x:500:\n")}
	s = &script{answers: app}
	if err := ApplyGroup(ctx, s, GroupSpec{Name: "app", GID: ptr(500)}); err != nil || len(s.ran) != 1 {
		t.Errorf("group in sync: %v, ran %q", err, s.ran)
	}
	s = &script{answers: app}
	if err := ApplyGroup(ctx, s, GroupSpec{Name: "app", GID: ptr(600)}); err != nil || s.ran[1] != "groupmod -g 600 -- 'app'" {
		t.Errorf("groupmod: %v, ran %q", err, s.ran)
	}
	s = &script{answers: map[string]ssh.Result{"getent group": {ExitCode: 2}}}
	if err := ApplyGroup(ctx, s, GroupSpec{Name: "app"}); err != nil || s.ran[1] != "groupadd -- 'app'" {
		t.Errorf("groupadd: %v, ran %q", err, s.ran)
	}
	if err := ApplyGroup(ctx, &script{lose: "getent"}, GroupSpec{Name: "app"}); !errors.Is(err, errLost) {
		t.Errorf("group read lost: %v", err)
	}
	if err := ApplyGroup(ctx, &script{}, GroupSpec{Name: "Bad"}); err == nil {
		t.Error("applied a bad group")
	}
	s = &script{answers: app}
	if err := DeleteGroup(ctx, s, "app"); err != nil || s.ran[1] != "groupdel -- 'app'" {
		t.Errorf("groupdel: %v, ran %q", err, s.ran)
	}
	s = &script{answers: map[string]ssh.Result{"getent group": {ExitCode: 2}}}
	if err := DeleteGroup(ctx, s, "app"); err != nil || len(s.ran) != 1 {
		t.Errorf("delete missing group: %v", err)
	}
	s = &script{answers: map[string]ssh.Result{"getent group": out("app:x:500:\n"), "groupdel": {ExitCode: 8, Stderr: []byte("group app is the primary group of deploy\n")}}}
	if err := DeleteGroup(ctx, s, "app"); err == nil || err.Error() != "groupdel: group app is the primary group of deploy" {
		t.Errorf("groupdel refused: %v", err)
	}
}
