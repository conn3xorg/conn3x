// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh/sshtest"
)

// TestProxyHelper isn't a test: with CONN3X_PROXY_TO set, it's the proxy
// command, piping stdin and stdout to that address as nc would.
func TestProxyHelper(t *testing.T) {
	to := os.Getenv("CONN3X_PROXY_TO")
	if to == "" {
		t.Skip("run as a proxy command")
	}
	c, err := net.Dial("tcp", to)
	if err != nil {
		os.Stderr.WriteString("proxy: " + err.Error() + "\n")
		os.Exit(2)
	}
	go func() { _, _ = io.Copy(c, os.Stdin) }()
	_, _ = io.Copy(os.Stdout, c)
	os.Exit(0)
}

// A host reached through proxy_command runs commands as over TCP, with the
// host key still checked end to end.
func TestProxyCommand(t *testing.T) {
	s := sshtest.New(t)
	t.Setenv("CONN3X_PROXY_TO", s.Addr)
	cfg := testConfig(t, s)
	cfg.Host = "web1.internal" // never resolved: the proxy reaches it
	cfg.KnownHostsFile = ""
	cfg.HostKey = strings.TrimSpace(string(gossh.MarshalAuthorizedKey(s.HostKey)))
	cfg.ProxyCommand = []string{os.Args[0], "-test.run=^TestProxyHelper$", "--", "%h:%p"}
	c := dial(t, cfg)
	defer c.Close()
	res, err := c.Run(context.Background(), "echo hi", nil)
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("run over the proxy: %+v, %v", res, err)
	}

	// The proxy's own complaint reaches the error.
	t.Setenv("CONN3X_PROXY_TO", "127.0.0.1:1")
	if _, err := Dial(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "proxy_command said: proxy:") {
		t.Fatalf("a failing proxy: err = %v", err)
	}

	cfg.Jumps = []Jump{{Host: "bastion", Port: 22}}
	if _, err := Dial(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "can't be combined") {
		t.Fatalf("proxy and jumps: err = %v", err)
	}
}

func TestExpandAndSplitProxyCommand(t *testing.T) {
	got, err := ExpandProxyCommand([]string{"aws", "ssm", "start-session", "--target", "%h", "--parameters", "portNumber=%p", "%r@%%"}, "i-0abc", 22, "ec2-user")
	if err != nil || !slices.Equal(got, []string{"aws", "ssm", "start-session", "--target", "i-0abc", "--parameters", "portNumber=22", "ec2-user@%"}) {
		t.Errorf("expand: %q, %v", got, err)
	}
	for _, bad := range [][]string{{"x", "%d"}, {"x", "50%"}} {
		if _, err := ExpandProxyCommand(bad, "h", 22, "u"); err == nil {
			t.Errorf("expanded %q", bad)
		}
	}
	args, err := SplitProxyCommand(`aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters 'portNumber=%p'`)
	if err != nil || len(args) != 9 || args[8] != "portNumber=%p" {
		t.Errorf("split: %q, %v", args, err)
	}
	for _, bad := range []string{"nc %h %p | tee log", "sh -c $X", "a 'b", ""} {
		if _, err := SplitProxyCommand(bad); err == nil {
			t.Errorf("split %q", bad)
		}
	}
}
