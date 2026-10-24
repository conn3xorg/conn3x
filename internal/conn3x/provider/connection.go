// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// connectionBlock is the "ssh" block every host resource carries. It is not
// called "connection" because OpenTofu reserves that name in resources for
// provisioners and strips it before the provider sees the configuration.
//
// There is deliberately no inline private key: resource attributes are
// stored in state, so a key would end up there. Point private_key_file at a
// key, or leave it unset to use the SSH agent.
func connectionBlock() *configschema.NestedBlock {
	return &configschema.NestedBlock{
		Nesting:  configschema.NestingSingle,
		MinItems: 1,
		MaxItems: 1,
		Block: configschema.Block{
			Description: "How to reach the host over SSH.",
			Attributes: map[string]*configschema.Attribute{
				"host":             {Type: cty.String, Required: true, Description: "Hostname or IP address."},
				"port":             {Type: cty.Number, Optional: true, Description: "SSH port. Defaults to 22."},
				"user":             {Type: cty.String, Required: true, Description: "User to log in as."},
				"private_key_file": {Type: cty.String, Optional: true, Description: "Path to a private key. Defaults to the SSH agent."},
				"host_key":         {Type: cty.String, Optional: true, Description: "Pinned host public key, in authorized_keys format."},
				"known_hosts_file": {Type: cty.String, Optional: true, Description: "known_hosts file to verify the host against. Defaults to ~/.ssh/known_hosts."},
				"become":           {Type: cty.Bool, Optional: true, Description: "Run commands as root through sudo."},
				"become_password_file": {
					Type:        cty.String,
					Optional:    true,
					Description: "File holding the sudo password, when sudo needs one. The password itself never goes into configuration or state.",
				},
			},
		},
	}
}

// hostConn runs module commands on one host, through sudo when the ssh
// block asks for become. Connections are pooled: every resource that names
// the same host and login in one run shares a single SSH connection.
type hostConn struct {
	client *ssh.Client
	runner modules.Runner
}

func (h *hostConn) Run(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	return h.runner.Run(ctx, cmd, stdin)
}

// Close returns the connection to the pool; it stays open for the run.
func (h *hostConn) Close() error { return nil }

type pooledConn struct {
	ready chan struct{} // closed once the dial finished
	conn  *hostConn
	err   error
}

var pool = struct {
	sync.Mutex
	conns map[string]*pooledConn
}{conns: map[string]*pooledConn{}}

// dialConnection returns a connection to the host an ssh block describes,
// reusing an open one when it is still alive.
func dialConnection(ctx context.Context, conn cty.Value) (*hostConn, error) {
	cfg, err := sshConfig(conn)
	if err != nil {
		return nil, err
	}
	become := conn.GetAttr("become")
	useSudo := !become.IsNull() && become.True()
	var password []byte
	if file := stringOr(conn.GetAttr("become_password_file"), ""); useSudo && file != "" {
		raw, err := os.ReadFile(expandHome(file))
		if err != nil {
			return nil, fmt.Errorf("reading become_password_file: %w", err)
		}
		password = []byte(strings.TrimRight(string(raw), "\r\n"))
	}
	key := poolKey(cfg, useSudo, password)

	pool.Lock()
	entry, ok := pool.conns[key]
	if ok {
		pool.Unlock()
		<-entry.ready
		if entry.err == nil && entry.conn.client.Alive() {
			return entry.conn, nil
		}
		pool.Lock()
		// Another caller may already have replaced the dead entry.
		if pool.conns[key] == entry {
			delete(pool.conns, key)
		}
		if again, ok := pool.conns[key]; ok {
			pool.Unlock()
			<-again.ready
			return again.conn, again.err
		}
	}
	entry = &pooledConn{ready: make(chan struct{})}
	pool.conns[key] = entry
	pool.Unlock()

	client, err := ssh.Dial(ctx, cfg)
	if err != nil {
		entry.err = err
		pool.Lock()
		delete(pool.conns, key) // let the next caller retry
		pool.Unlock()
		close(entry.ready)
		return nil, err
	}
	h := &hostConn{client: client, runner: client}
	if useSudo {
		h.runner = &ssh.Become{Client: client, Password: password}
	}
	entry.conn = h
	close(entry.ready)
	return h, nil
}

func poolKey(cfg ssh.Config, become bool, password []byte) string {
	sum := sha256.New()
	for _, part := range [][]byte{
		[]byte(cfg.Host), []byte(strconv.Itoa(cfg.Port)), []byte(cfg.User), cfg.PrivateKey,
		[]byte(cfg.HostKey), []byte(cfg.KnownHostsFile), []byte(strconv.FormatBool(become)), password,
	} {
		sum.Write(part)
		sum.Write([]byte{0})
	}
	return hex.EncodeToString(sum.Sum(nil))
}

func sshConfig(conn cty.Value) (ssh.Config, error) {
	if conn.IsNull() || !conn.IsWhollyKnown() {
		return ssh.Config{}, fmt.Errorf("the ssh block is not known yet")
	}
	cfg := ssh.Config{
		Host:           conn.GetAttr("host").AsString(),
		User:           conn.GetAttr("user").AsString(),
		HostKey:        stringOr(conn.GetAttr("host_key"), ""),
		KnownHostsFile: expandHome(stringOr(conn.GetAttr("known_hosts_file"), "")),
	}
	if port := conn.GetAttr("port"); !port.IsNull() {
		p, acc := port.AsBigFloat().Int64()
		if acc != big.Exact || p < 1 || p > 65535 {
			return ssh.Config{}, fmt.Errorf("ssh port must be between 1 and 65535")
		}
		cfg.Port = int(p)
	}
	if keyFile := stringOr(conn.GetAttr("private_key_file"), ""); keyFile != "" {
		key, err := os.ReadFile(expandHome(keyFile))
		if err != nil {
			return ssh.Config{}, fmt.Errorf("reading private_key_file: %w", err)
		}
		cfg.PrivateKey = key
	}
	return cfg, nil
}

func stringOr(v cty.Value, fallback string) string {
	if v.IsNull() || !v.IsKnown() {
		return fallback
	}
	return v.AsString()
}

func expandHome(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return home + path[1:]
		}
	}
	return path
}
