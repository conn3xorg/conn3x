// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sync"

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
		return append(a, c.container, "--", "/bin/sh", "-c", ssh.Prelude+cmd)
	default:
		if c.user != "" {
			a = append(a, "--user", c.user)
		}
		return append(a, c.container, "/bin/sh", "-c", ssh.Prelude+cmd)
	}
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
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit) && ctx.Err() == nil:
		// The engine's own failures share codes a command can exit with,
		// and which ones differs between engines and versions, so a code
		// it uses is only the command's while the container still runs.
		switch exit.ExitCode() {
		case 125, 126, 127, 255:
			if !c.running(ctx) {
				return res, fmt.Errorf("%s exec %s: the container isn't running: %s", c.engine, c.container, bytes.TrimSpace(res.Stderr))
			}
		}
		res.ExitCode = exit.ExitCode()
		return res, nil
	case err != nil:
		return res, fmt.Errorf("%s exec %s: %w", c.engine, c.container, err)
	}
	return res, nil
}

// running asks the engine whether the container is running.
func (c *containerConn) running(ctx context.Context) bool {
	var args []string
	switch c.engine {
	case "kubectl":
		if c.context != "" {
			args = append(args, "--context", c.context)
		}
		args = append(args, "get", "pod", c.container, "-o", "jsonpath={.status.phase}")
		if c.namespace != "" {
			args = append(args, "-n", c.namespace)
		}
		out, err := exec.CommandContext(ctx, c.engine, args...).Output()
		return err == nil && string(out) == "Running"
	default:
		out, err := exec.CommandContext(ctx, c.engine, "container", "inspect", "-f", "{{.State.Running}}", c.container).Output()
		return err == nil && string(bytes.TrimSpace(out)) == "true"
	}
}

// Alive reports whether a command still runs in the container.
func (c *containerConn) Alive() bool {
	res, err := c.Run(context.Background(), "true", nil)
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
