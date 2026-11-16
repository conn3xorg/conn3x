// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package debconf

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

func TestValidate(t *testing.T) {
	ok := Selection{"postfix", "postfix/main_mailer_type", "select", "Internet Site"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]Selection{
		"flag as package":   {"-h", "postfix/main_mailer_type", "select", "x"},
		"space in question": {"postfix", "postfix/main mailer", "select", "x"},
		"unknown type":      {"postfix", "postfix/main_mailer_type", "seen", "x"},
		"two lines":         {"postfix", "postfix/mailname", "string", "a\nb"},
		"boolean yes":       {"app", "app/enable", "boolean", "yes"},
	} {
		if s.Validate() == nil {
			t.Errorf("%s: accepted %+v", name, s)
		}
	}
}

// debconfHost shows what debconf-show prints, and answers GET with the
// password it holds, as a Debian host does.
type debconfHost struct {
	shown, password string
	ran             []string
}

func (h *debconfHost) Run(_ context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	h.ran = append(h.ran, cmd+"<"+string(stdin))
	switch {
	case strings.HasPrefix(cmd, "debconf-show "):
		return ssh.Result{Stdout: []byte(h.shown)}, nil
	case strings.HasSuffix(cmd, "debconf-communicate"):
		if h.password == "" {
			return ssh.Result{Stdout: []byte("10 app/db_password doesn't exist\n")}, nil
		}
		return ssh.Result{Stdout: []byte("0 " + h.password + "\n")}, nil
	case strings.HasPrefix(cmd, "cat /etc/os-release"):
		return ssh.Result{Stdout: []byte("ID=debian\n")}, nil
	}
	return ssh.Result{}, nil
}

func TestReadFindsTheQuestionAmongThePackages(t *testing.T) {
	h := &debconfHost{shown: "  postfix/mailname: mail.example.com\n* postfix/main_mailer_type: Internet Site\n* postfix/root_address:\n"}
	for q, want := range map[string]string{"postfix/mailname": "mail.example.com", "postfix/main_mailer_type": "Internet Site", "postfix/root_address": ""} {
		got, ok, err := Read(context.Background(), h, Selection{"postfix", q, "string", ""})
		if err != nil || !ok || got != want {
			t.Errorf("%s = %q, %v, %v; want %q", q, got, ok, err, want)
		}
	}
	if _, ok, _ := Read(context.Background(), h, Selection{"postfix", "postfix/mailname2", "string", ""}); ok {
		t.Error("found a question that isn't there")
	}
}

// debconf-show prints "(password omitted)" for a password, so Read asks
// debconf itself, and Apply fails when the answer didn't take.
func TestPasswordReadsThroughDebconfCommunicate(t *testing.T) {
	h := &debconfHost{shown: "* app/db_password: (password omitted)\n", password: "s3cret"}
	s := Selection{"app", "app/db_password", "password", "s3cret"}
	got, ok, err := Read(context.Background(), h, s)
	if err != nil || !ok || got != "s3cret" {
		t.Fatalf("read %q, %v, %v", got, ok, err)
	}
	if err := Apply(context.Background(), h, s); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(h.ran, "\n"), "debconf-set-selections<app app/db_password password s3cret\n") {
		t.Errorf("ran %q", h.ran)
	}
	h.password = ""
	if err := Apply(context.Background(), h, s); err == nil || !strings.Contains(err.Error(), "debconf kept") {
		t.Errorf("apply with a host that dropped the answer: %v", err)
	}
	h.password = "old-s3cret"
	if err := Apply(context.Background(), h, s); err == nil || strings.Contains(err.Error(), "old-s3cret") {
		t.Errorf("apply with a host that kept another password: %v", err)
	}
}

// lockedHost answers like a host where apt holds debconf's database for
// the first few commands.
type lockedHost struct {
	debconfHost
	locked int
}

func (h *lockedHost) Run(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	if h.locked > 0 && strings.Contains(cmd, "debconf-") {
		h.locked--
		h.ran = append(h.ran, cmd)
		return ssh.Result{ExitCode: 1, Stderr: []byte(`debconf: DbDriver "config": /var/cache/debconf/config.dat is locked by another process: Resource temporarily unavailable` + "\n")}, nil
	}
	return h.debconfHost.Run(ctx, cmd, stdin)
}

// A locked database is waited out, not an error, until lockWait has passed.
func TestWaitsOutTheDatabaseLock(t *testing.T) {
	savedWait, savedPoll := lockWait, lockPoll
	lockWait, lockPoll = time.Second, time.Millisecond
	defer func() { lockWait, lockPoll = savedWait, savedPoll }()

	h := &lockedHost{debconfHost: debconfHost{shown: "* tzdata/Areas: Europe\n"}, locked: 2}
	got, ok, err := Read(context.Background(), h, Selection{Package: "tzdata", Question: "tzdata/Areas", Type: "select", Value: "Europe"})
	if err != nil || !ok || got != "Europe" {
		t.Fatalf("read after the lock: %q, %v, %v", got, ok, err)
	}

	lockWait = 10 * time.Millisecond
	h = &lockedHost{debconfHost: debconfHost{shown: "* tzdata/Areas: Europe\n"}, locked: 1 << 20}
	if _, _, err := Read(context.Background(), h, Selection{Package: "tzdata", Question: "tzdata/Areas", Type: "select", Value: "Europe"}); err == nil || !strings.Contains(err.Error(), "is locked by another process") {
		t.Fatalf("a lock that never clears: %v", err)
	}
}
