// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/zclconf/go-cty/cty"
	gossh "golang.org/x/crypto/ssh"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// conn3x_test_container is a throwaway host for conn3x test: a container
// on this machine that boots systemd and sshd, such as the images
// test/images publishes, with a key made for it. A setup run creates it,
// later runs apply circuits to it, and the end of the test file removes
// it (#799).

func testContainerSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Experimental. A throwaway host for conn3x test: a Podman container on the machine running Conn3x that boots systemd and sshd, such as ghcr.io/conn3xorg/test-rocky10. Conn3x makes it a key, and destroying the resource removes the container. Never for anything you want to keep.",
		Attributes: map[string]*configschema.Attribute{
			"id":               {Type: cty.String, Computed: true, Description: "The container's ID."},
			"image":            {Type: cty.String, Required: true, Description: "An image that boots systemd and runs sshd, with an empty /root/.ssh, such as ghcr.io/conn3xorg/test-rocky10, test-debian13 or test-ubuntu2404."},
			"address":          {Type: cty.String, Computed: true, Description: "Where the container's sshd listens: 127.0.0.1."},
			"port":             {Type: cty.Number, Computed: true, Description: "The port on 127.0.0.1 that reaches the container's sshd."},
			"user":             {Type: cty.String, Computed: true, Description: "The user to log in as: root."},
			"private_key_file": {Type: cty.String, Computed: true, Description: "The key Conn3x made for this container, which root's authorized_keys holds."},
			"known_hosts_file": {Type: cty.String, Computed: true, Description: "A known_hosts file with the container's host key, for the ssh block's known_hosts_file."},
		},
	}}
}

func validateTestContainer(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() {
		return diags
	}
	if img := cfg.GetAttr("image"); known(img) && (strings.TrimSpace(img.AsString()) == "" || strings.HasPrefix(img.AsString(), "-")) {
		diags = diags.Append(attrError("image", "image must name an image, such as ghcr.io/conn3xorg/test-rocky10"))
	}
	return diags
}

// testContainerLabel marks every container conn3x_test_container starts,
// so a run that was killed can be cleaned up with podman ps --filter.
const testContainerLabel = "io.conn3x.test-container=true"

var testContainerComputed = []string{"id", "address", "port", "user", "private_key_file", "known_hosts_file"}

func planTestContainer(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	var resp providers.PlanResourceChangeResponse
	if req.ProposedNewState.IsNull() {
		resp.PlannedState = req.ProposedNewState
		return resp
	}
	if !req.PriorState.IsNull() && req.PriorState.GetAttr("image").RawEquals(req.ProposedNewState.GetAttr("image")) {
		resp.PlannedState = req.PriorState
		return resp
	}
	vals := req.ProposedNewState.AsValueMap()
	for _, a := range testContainerComputed {
		vals[a] = cty.UnknownVal(vals[a].Type())
	}
	if !req.PriorState.IsNull() {
		resp.RequiresReplace = []cty.Path{cty.GetAttrPath("image")}
	}
	resp.PlannedState = cty.ObjectVal(vals)
	return resp
}

// podman runs podman with args and returns what it printed.
var podman = func(ctx context.Context, args ...string) (string, error) {
	if _, err := exec.LookPath("podman"); err != nil {
		return "", errors.New("conn3x_test_container needs Podman on the machine running Conn3x, and podman isn't on the PATH")
	}
	var out, errOut bytes.Buffer
	cmd := exec.CommandContext(ctx, "podman", args...)
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("podman %s: %w: %s", args[0], err, strings.TrimSpace(errOut.String()))
	}
	return out.String(), nil
}

func readTestContainer(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	// Gone, as when someone removed it by hand: the next plan makes another.
	if _, err := podman(ctx, "container", "exists", req.PriorState.GetAttr("id").AsString()); err != nil {
		resp.NewState = cty.NullVal(req.PriorState.Type())
	}
	return resp
}

func applyTestContainer(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	if req.PlannedState.IsNull() {
		id := req.PriorState.GetAttr("id").AsString()
		if _, err := podman(ctx, "rm", "-f", id); err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(err)
			return resp
		}
		_ = os.RemoveAll(filepath.Dir(req.PriorState.GetAttr("private_key_file").AsString()))
		resp.NewState = req.PlannedState
		return resp
	}
	state, err := startTestContainer(ctx, req.PlannedState)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("conn3x_test_container: %w", err))
		return resp
	}
	resp.NewState = state
	return resp
}

func startTestContainer(ctx context.Context, planned cty.Value) (_ cty.Value, err error) {
	image := planned.GetAttr("image").AsString()
	dir, err := os.MkdirTemp("", "conn3x-test-container-")
	if err != nil {
		return cty.NilVal, err
	}
	keyFile, hostsFile := filepath.Join(dir, "id_ed25519"), filepath.Join(dir, "known_hosts")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return cty.NilVal, err
	}
	block, err := gossh.MarshalPrivateKey(priv, "conn3x test container")
	if err != nil {
		return cty.NilVal, err
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(block), 0o600); err != nil {
		return cty.NilVal, err
	}
	sshPub, err := gossh.NewPublicKey(pub)
	if err != nil {
		return cty.NilVal, err
	}

	// Podman's default capabilities differ between versions. A real host's
	// root can read /etc/shadow and write audit records, and PAM needs both
	// to let other users log in, as test/e2e does.
	out, err := podman(ctx, "run", "-d", "--rm", "--label", testContainerLabel, "--systemd=always", "--cap-add", "DAC_OVERRIDE,AUDIT_WRITE", "-p", "127.0.0.1::22", image)
	if err != nil {
		_ = os.RemoveAll(dir)
		return cty.NilVal, err
	}
	id := strings.TrimSpace(out)
	defer func() {
		if err != nil {
			_, _ = podman(context.Background(), "rm", "-f", id)
			_ = os.RemoveAll(dir)
		}
	}()
	out, err = podman(ctx, "port", id, "22/tcp")
	if err != nil {
		return cty.NilVal, err
	}
	_, portText, err := net.SplitHostPort(strings.TrimSpace(strings.SplitN(out, "\n", 2)[0]))
	if err != nil {
		return cty.NilVal, fmt.Errorf("podman port printed %q, not an address and port", strings.TrimSpace(out))
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return cty.NilVal, fmt.Errorf("podman port printed the port %q", portText)
	}
	// Services that start late can restart sshd under the first login.
	// Degraded is fine for a test host, so the exit status doesn't matter.
	_, _ = podman(ctx, "exec", id, "timeout", "60", "systemctl", "is-system-running", "--wait")
	if _, err := podman(ctx, "exec", id, "sh", "-c", "umask 077 && mkdir -p /root/.ssh && printf '%s\\n' \"$1\" > /root/.ssh/authorized_keys", "sh",
		strings.TrimSpace(string(gossh.MarshalAuthorizedKey(sshPub)))); err != nil {
		return cty.NilVal, err
	}
	hostKey, err := podman(ctx, "exec", id, "cat", "/etc/ssh/ssh_host_ed25519_key.pub")
	if err != nil {
		return cty.NilVal, fmt.Errorf("the image has no ed25519 host key at /etc/ssh/ssh_host_ed25519_key.pub, so Conn3x can't pin it: %w", err)
	}
	f := strings.Fields(hostKey)
	if len(f) < 2 {
		return cty.NilVal, errors.New("the container's ed25519 host key is empty")
	}
	if err := os.WriteFile(hostsFile, []byte(fmt.Sprintf("[127.0.0.1]:%d %s %s\n", port, f[0], f[1])), 0o600); err != nil {
		return cty.NilVal, err
	}
	if err := waitForSSH(ctx, port); err != nil {
		return cty.NilVal, err
	}
	vals := planned.AsValueMap()
	vals["id"], vals["address"], vals["port"], vals["user"] = cty.StringVal(id), cty.StringVal("127.0.0.1"), cty.NumberIntVal(int64(port)), cty.StringVal("root")
	vals["private_key_file"], vals["known_hosts_file"] = cty.StringVal(keyFile), cty.StringVal(hostsFile)
	return cty.ObjectVal(vals), nil
}

// waitForSSH waits until something answers on the port with an SSH banner.
func waitForSSH(ctx context.Context, port int) error {
	deadline := time.Now().Add(time.Minute)
	for {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 2*time.Second)
		if err == nil {
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 4)
			_, rerr := c.Read(buf)
			_ = c.Close()
			if rerr == nil && string(buf) == "SSH-" {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("sshd in the container didn't answer on 127.0.0.1:%d within a minute; check the image runs sshd", port)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}
