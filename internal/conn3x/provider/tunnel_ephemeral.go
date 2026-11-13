// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

const tunnelType = "conn3x_ssh_tunnel"

func tunnelSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A local port, open for the length of the run, that reaches remote from the host over Conn3x's SSH connection, jump hosts included, as ssh -L does. Give its local_host and local_port to another provider, such as one for the database the host runs. Nothing of it lands in state.",
		Attributes: map[string]*configschema.Attribute{
			"remote":     {Type: cty.String, Required: true, Description: "What to reach, as the host sees it: host:port, such as 127.0.0.1:5432 for a database on the host's loopback, or 10.0.2.7:6379 for one beside it."},
			"local_host": {Type: cty.String, Computed: true, Description: "Where the tunnel listens on this machine: 127.0.0.1."},
			"local_port": {Type: cty.Number, Computed: true, Description: "The port it listens on, chosen when the run opens it."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func validateTunnel(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() {
		return diags
	}
	if r := cfg.GetAttr("remote"); known(r) {
		host, port, err := net.SplitHostPort(r.AsString())
		if n, perr := strconv.Atoi(port); err != nil || host == "" || perr != nil || n < 1 || n > 65535 {
			diags = diags.Append(attrError("remote", fmt.Sprintf("remote %q must be host:port, such as 127.0.0.1:5432", r.AsString())))
		}
	}
	return diags.Append(validateSSH(cfg))
}

// tunnel is one open conn3x_ssh_tunnel.
type tunnel struct {
	client   *ssh.Client
	listener net.Listener
	remote   string
	mu       sync.Mutex
	conns    []net.Conn
	done     sync.WaitGroup
}

var tunnels = struct {
	sync.Mutex
	m map[string]*tunnel
}{m: map[string]*tunnel{}}

// openTunnel dials the host on its own connection, outside the pool, so the
// tunnel lives exactly as long as the run says, and listens on loopback.
func openTunnel(ctx context.Context, req providers.OpenEphemeralResourceRequest) providers.OpenEphemeralResourceResponse {
	var resp providers.OpenEphemeralResourceResponse
	cfg := req.Config
	cc, err := sshConfig(cfg.GetAttr("ssh"))
	if err == nil {
		var c *ssh.Client
		c, err = ssh.Dial(ctx, cc)
		if err == nil {
			resp, err = startTunnel(c, cfg)
			if err != nil {
				_ = c.Close()
			}
		}
	}
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("%s: %w", tunnelType, err))
	}
	return resp
}

func startTunnel(c *ssh.Client, cfg cty.Value) (providers.OpenEphemeralResourceResponse, error) {
	var resp providers.OpenEphemeralResourceResponse
	remote := cfg.GetAttr("remote").AsString()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return resp, err
	}
	t := &tunnel{client: c, listener: l, remote: remote}
	go t.serve()
	id := make([]byte, 8)
	_, _ = rand.Read(id)
	key := hex.EncodeToString(id)
	tunnels.Lock()
	tunnels.m[key] = t
	tunnels.Unlock()
	port := l.Addr().(*net.TCPAddr).Port
	log.Printf("[INFO] conn3x: %s: 127.0.0.1:%d reaches %s from %s", tunnelType, port, remote, c.Addr())
	vals := cfg.AsValueMap()
	vals["local_host"] = cty.StringVal("127.0.0.1")
	vals["local_port"] = cty.NumberIntVal(int64(port))
	resp.Result = cty.ObjectVal(vals)
	resp.Private = []byte(key)
	return resp, nil
}

// serve forwards each local connection to remote over its own channel.
func (t *tunnel) serve() {
	for {
		local, err := t.listener.Accept()
		if err != nil {
			return // closed
		}
		t.done.Add(1)
		go func() {
			defer t.done.Done()
			defer local.Close()
			far, err := t.client.DialRemote(context.Background(), t.remote)
			if err != nil {
				log.Printf("[WARN] conn3x: %s: %v", tunnelType, err)
				return
			}
			defer far.Close()
			t.mu.Lock()
			t.conns = append(t.conns, local, far)
			t.mu.Unlock()
			copied := make(chan struct{}, 2)
			go func() { _, _ = io.Copy(far, local); copied <- struct{}{} }()
			go func() { _, _ = io.Copy(local, far); copied <- struct{}{} }()
			<-copied // one side ended: close both
		}()
	}
}

func (t *tunnel) close() error {
	err := t.listener.Close()
	t.mu.Lock()
	for _, c := range t.conns {
		_ = c.Close()
	}
	t.mu.Unlock()
	t.done.Wait()
	return errors.Join(err, t.client.Close())
}

func closeTunnel(req providers.CloseEphemeralResourceRequest) providers.CloseEphemeralResourceResponse {
	var resp providers.CloseEphemeralResourceResponse
	tunnels.Lock()
	t, ok := tunnels.m[string(req.Private)]
	delete(tunnels.m, string(req.Private))
	tunnels.Unlock()
	if ok {
		if err := t.close(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("[WARN] conn3x: closing %s: %v", tunnelType, err)
		}
	}
	return resp
}

// closeTunnels closes every tunnel still open, as when the provider stops.
func closeTunnels() {
	tunnels.Lock()
	open := tunnels.m
	tunnels.m = map[string]*tunnel{}
	tunnels.Unlock()
	for _, t := range open {
		_ = t.close()
	}
}
