// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// containers holds one hostConn per container, as pooled does per SSH host.
var containers sync.Map // key string => *hostConn

// inContainer reports whether an ssh block names a container to exec into
// instead of a host to log in to.
func inContainer(conn cty.Value) bool {
	v := optional(conn, "container")
	return !v.IsNull() && v.IsKnown() && v.AsString() != ""
}

// containerHost is the connection for an ssh block with container set:
// each command runs with the engine's exec, and nothing is kept open.
func containerHost(conn cty.Value) (*hostConn, error) {
	c, err := execTarget(conn)
	if err != nil {
		return nil, err
	}
	key := fmt.Sprintf("%q", c.args(""))
	if h, ok := containers.Load(key); ok {
		return h.(*hostConn), nil
	}
	h, _ := containers.LoadOrStore(key, &hostConn{client: c, runner: c, host: c.Addr(), rootKey: "container\x00" + key})
	return h.(*hostConn), nil
}

func execTarget(conn cty.Value) (*containerConn, error) {
	c := &containerConn{
		engine:    stringOr(optional(conn, "container_engine"), "podman"),
		container: optional(conn, "container").AsString(),
		namespace: stringOr(optional(conn, "kube_namespace"), ""),
		context:   stringOr(optional(conn, "kube_context"), ""),
		user:      stringOr(optional(conn, "user"), ""),
	}
	if b := optional(conn, "become"); !b.IsNull() && b.IsKnown() && b.True() {
		c.user = "0"
	}
	switch c.engine {
	case "podman", "docker":
		if c.namespace != "" || c.context != "" {
			return nil, fmt.Errorf("kube_namespace and kube_context go with container_engine = \"kubectl\", not %q", c.engine)
		}
	case "kubectl":
		if c.user != "" {
			return nil, errors.New("kubectl exec runs as the container's own user, so user and become can't be set with container_engine = \"kubectl\"")
		}
	default:
		return nil, fmt.Errorf("container_engine is \"podman\", \"docker\" or \"kubectl\", not %q", c.engine)
	}
	return c, nil
}

// containerConn runs commands in a container through its engine's exec on
// the machine Conn3x runs on. It has no Starter, Dialer or Shell, so the
// agent stays off and steps that need SSH say so.
type containerConn struct {
	engine, container, namespace, context, user string
}

// args is the engine's command line for running cmd in the container.
func (c *containerConn) args(cmd string) []string {
	a := []string{"exec", "-i"}
	switch c.engine {
	case "kubectl":
		if c.context != "" {
			a = append([]string{"--context", c.context}, a...)
		}
		if c.namespace != "" {
			a = append(a, "-n", c.namespace)
		}
		return append(append(a, c.container, "--"), reported(cmd)...)
	default:
		if c.user != "" {
			a = append(a, "--user", c.user)
		}
		return append(append(a, c.container), reported(cmd)...)
	}
}

// exitMark starts the line the shell in the container writes to stderr
// with the command's exit status.
const exitMark = "\n\x01conn3x-exit:"

// reported runs cmd in a shell that writes its exit status to stderr after
// it, as exitMark and the number. The engines' own failures exit with codes
// a command can use too, and differ between engines and versions, so a run
// without that line is the engine's failure, whatever its code. The inner
// shell keeps an exit in cmd from skipping the report.
func reported(cmd string) []string {
	return []string{"/bin/sh", "-c", `/bin/sh -c "$1"; rc=$?; printf '\n\001conn3x-exit:%d\n' "$rc" >&2; exit "$rc"`, "conn3x", ssh.Prelude + cmd}
}

func (c *containerConn) Run(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	x := exec.CommandContext(ctx, c.engine, c.args(cmd)...)
	stdout, stderr := &cappedBuf{}, &cappedBuf{}
	x.Stdin, x.Stdout, x.Stderr = bytes.NewReader(stdin), stdout, stderr
	err := x.Run()
	if stdout.over || stderr.over {
		return ssh.Result{}, fmt.Errorf("%s: the command printed more than %d MiB, the most conn3x reads from one command on a host", c.Addr(), ssh.MaxOutput>>20)
	}
	res := ssh.Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if ctx.Err() != nil {
		return res, ctx.Err()
	}
	i := bytes.LastIndex(res.Stderr, []byte(exitMark))
	code, convErr := -1, error(nil)
	if i >= 0 {
		code, convErr = strconv.Atoi(strings.TrimSuffix(string(res.Stderr[i+len(exitMark):]), "\n"))
	}
	if i < 0 || convErr != nil {
		why := string(bytes.TrimSpace(res.Stderr))
		if why == "" && err != nil {
			why = err.Error()
		}
		return ssh.Result{Stdout: res.Stdout}, fmt.Errorf("%s exec %s: %s", c.engine, c.container, why)
	}
	res.Stderr, res.ExitCode = res.Stderr[:i], code
	return res, nil
}

// Alive reports whether a command still runs in the container.
func (c *containerConn) Alive() bool {
	// kubectl has no request timeout of its own.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res, err := c.Run(ctx, "true", nil)
	return err == nil && res.ExitCode == 0
}

func (c *containerConn) Addr() string { return c.engine + ":" + c.container }

func (c *containerConn) Close() error { return nil }

// cappedBuf keeps up to ssh.MaxOutput bytes and notes when more came.
type cappedBuf struct {
	bytes.Buffer
	over bool
}

func (b *cappedBuf) Write(p []byte) (int, error) {
	if b.Len()+len(p) > ssh.MaxOutput {
		b.over = true
		return 0, errors.New("output over the limit")
	}
	return b.Buffer.Write(p)
}
