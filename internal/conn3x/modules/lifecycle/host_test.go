// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package lifecycle

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// answer gives every run the same result, and records the commands.
type answer struct {
	res  ssh.Result
	err  error
	cmds []string
}

func (a *answer) Run(_ context.Context, cmd string, _ []byte) (ssh.Result, error) {
	a.cmds = append(a.cmds, cmd)
	return a.res, a.err
}

var errLost = errors.New("connection lost")

func TestWaitOnTheHost(t *testing.T) {
	ctx := context.Background()
	// No timeout waits DefaultWait, counted in seconds on the host.
	h := &answer{}
	if err := (WaitFor{Port: 8080}).Wait(ctx, h); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.cmds[0], `[ "$i" -ge 300 ]`) || !strings.Contains(h.cmds[0], "awk -v p=1F90 ") || !strings.Contains(h.cmds[0], "waiting for port 8080") {
		t.Errorf("script:\n%s", h.cmds[0])
	}
	h = &answer{res: ssh.Result{ExitCode: 1, Stderr: []byte("timed out after 5m0s waiting for port 8080\n")}}
	if err := (WaitFor{Port: 8080}).Wait(ctx, h); err == nil || err.Error() != "timed out after 5m0s waiting for port 8080" {
		t.Errorf("timed out: %v", err)
	}
	if err := (WaitFor{Port: 8080}).Wait(ctx, &answer{err: errLost}); !errors.Is(err, errLost) {
		t.Errorf("lost: %v", err)
	}
	if err := (WaitFor{Path: "/a\nb"}).Wait(ctx, h); err == nil || !strings.Contains(err.Error(), "must be an absolute path") {
		t.Errorf("newline in path: %v", err)
	}
	if ok, err := (WaitFor{Port: 22}).Ready(ctx, &answer{}); !ok || err != nil {
		t.Errorf("ready: %v, %v", ok, err)
	}
	if _, err := (WaitFor{Port: 22}).Ready(ctx, &answer{err: errLost}); !errors.Is(err, errLost) {
		t.Errorf("ready, lost: %v", err)
	}
	for want, w := range map[string]WaitFor{"port 22": {Port: 22}, "/run/x": {Path: "/run/x"}, "http://x/": {URL: URLCheck{URL: "http://x/"}}} {
		if got := w.String(); got != want {
			t.Errorf("String() = %q, want %q", got, want)
		}
	}
}

func TestBootIDAndReboot(t *testing.T) {
	ctx := context.Background()
	if id, err := BootID(ctx, &answer{res: ssh.Result{Stdout: []byte("1b2c\n")}}); err != nil || id != "1b2c" {
		t.Errorf("boot id %q, %v", id, err)
	}
	if _, err := BootID(ctx, &answer{res: ssh.Result{ExitCode: 1, Stderr: []byte("No such file\n")}}); err == nil || err.Error() != "reading the boot id: No such file" {
		t.Errorf("unreadable: %v", err)
	}
	if _, err := BootID(ctx, &answer{err: errLost}); !errors.Is(err, errLost) {
		t.Errorf("lost: %v", err)
	}
	h := &answer{}
	if err := ScheduleReboot(ctx, h); err != nil || !strings.HasPrefix(h.cmds[0], "nohup sh -c 'sleep 2; systemctl reboot || reboot'") || !strings.HasSuffix(h.cmds[0], "&") {
		t.Errorf("%v, ran %q", err, h.cmds)
	}
	if err := ScheduleReboot(ctx, &answer{res: ssh.Result{ExitCode: 1, Stderr: []byte("nohup: denied")}}); err == nil || err.Error() != "scheduling a reboot: nohup: denied" {
		t.Errorf("refused: %v", err)
	}
	if err := ScheduleReboot(ctx, &answer{err: errLost}); !errors.Is(err, errLost) {
		t.Errorf("lost: %v", err)
	}
}

// failDial is a host whose connection can't open a channel.
type failDial struct {
	answer
	err error
}

func (f *failDial) DialRemote(context.Context, string) (net.Conn, error) { return nil, f.err }

func TestURLCannotConnect(t *testing.T) {
	ctx := context.Background()
	w := WaitFor{URL: URLCheck{URL: "http://127.0.0.1:1/"}}
	// Nothing listening is something to wait out, not an error.
	if ok, err := w.Ready(ctx, &failDial{err: errors.New("connect failed")}); ok || err != nil {
		t.Errorf("refused: %v, %v", ok, err)
	}
	// sshd that never forwards would keep the wait going forever.
	_, err := w.Ready(ctx, &failDial{err: errors.New("ssh: rejected: administratively prohibited (open failed)")})
	if err == nil || !strings.Contains(err.Error(), "doesn't allow TCP forwarding") {
		t.Errorf("no forwarding: %v", err)
	}
	if err := (WaitFor{URL: URLCheck{URL: "http://127.0.0.1:1/"}, Timeout: time.Hour}).Wait(ctx, &failDial{err: errors.New("ssh: rejected: administratively prohibited")}); err == nil || !strings.Contains(err.Error(), "TCP forwarding") {
		t.Errorf("wait, no forwarding: %v", err)
	}
	// A cancelled wait stops at once, without waiting out the second.
	done, cancel := context.WithCancel(ctx)
	cancel()
	if err := (WaitFor{URL: URLCheck{URL: "http://127.0.0.1:1/"}, Timeout: time.Hour}).Wait(done, &failDial{err: errors.New("connect failed")}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
	if _, err := Do(ctx, &failDial{err: errLost}, Request{URLCheck: URLCheck{URL: "http://x/"}}); !errors.Is(err, errLost) {
		t.Errorf("Do, lost: %v", err)
	}
	if _, err := Do(ctx, noDial{}, Request{URLCheck: URLCheck{URL: "http://x/"}}); err == nil || !strings.Contains(err.Error(), "uri needs the SSH connection") {
		t.Errorf("Do, no dialer: %v", err)
	}
	if _, err := Do(ctx, &failDial{}, Request{URLCheck: URLCheck{URL: "ftp://x/"}}); err == nil || !strings.Contains(err.Error(), "must start with http") {
		t.Errorf("Do, invalid: %v", err)
	}
	if _, err := Do(ctx, &failDial{}, Request{URLCheck: URLCheck{URL: "http://x/"}, Method: "BAD METHOD"}); err == nil {
		t.Error("Do with a method net/http refuses")
	}
	if err := (URLCheck{URL: "http://x/%zz"}).Validate(); err == nil || !strings.HasPrefix(err.Error(), `url "http://x/%zz": `) {
		t.Errorf("unparsable: %v", err)
	}
}
