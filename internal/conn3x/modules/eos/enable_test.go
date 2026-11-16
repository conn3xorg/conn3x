// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package eos

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// enableSwitch answers as cEOS-lab does to commands on stdin after enable:
// the prompt on stderr, and with a wrong password three prompts and exit 1.
type enableSwitch struct {
	password string
	gotCmd   string
	gotIn    string
}

func (s *enableSwitch) RunRaw(_ context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	s.gotCmd, s.gotIn = cmd, string(stdin)
	lines := strings.Split(strings.TrimSuffix(string(stdin), "\n"), "\n")
	if lines[0] != "enable" || len(lines) < 2 || lines[1] != s.password {
		return ssh.Result{ExitCode: 1, Stderr: []byte("Password: \nPassword: \nPassword: ")}, nil
	}
	return ssh.Result{Stdout: []byte("Current privilege level is 15\necho " + s.password + "\n"), Stderr: []byte("Password: ")}, nil
}

func TestEnable(t *testing.T) {
	sw := &enableSwitch{password: "EnPass1"}
	d := Enable{Device: sw, Password: []byte("EnPass1")}
	out, err := Show(context.Background(), d, "show privilege")
	if err != nil {
		t.Fatal(err)
	}
	if sw.gotCmd != "" || sw.gotIn != "enable\nEnPass1\nshow privilege\n" {
		t.Errorf("sent cmd %q, stdin %q", sw.gotCmd, sw.gotIn)
	}
	if !strings.Contains(out, "privilege level is 15") || strings.Contains(out, "EnPass1") {
		t.Errorf("output %q", out)
	}

	// Config session lines go after enable as they are.
	if _, err := run(context.Background(), d, "", []byte("configure session s1\nhostname x\n")); err != nil {
		t.Fatal(err)
	}
	if sw.gotIn != "enable\nEnPass1\nconfigure session s1\nhostname x\n" {
		t.Errorf("stdin %q", sw.gotIn)
	}

	_, err = Show(context.Background(), Enable{Device: sw, Password: []byte("wrong")}, "show privilege")
	if !errors.Is(err, ErrEnableRefused) {
		t.Errorf("wrong password: %v", err)
	}
}
