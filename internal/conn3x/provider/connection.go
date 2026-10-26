// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	sshconfig "github.com/kevinburke/ssh_config"
	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/agent"
	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
	"github.com/opentofu/opentofu/internal/conn3x/version"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
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
				"host": {Type: cty.String, Required: true, Description: "Hostname or IP address."},
				"port": {Type: cty.Number, Optional: true, Description: "SSH port. Defaults to 22."},
				"user": {Type: cty.String, Optional: true, Description: "User to log in as. Required unless ssh_config_file sets one."},
				"jump_hosts": {
					Type:        cty.List(cty.String),
					Optional:    true,
					Description: "Hosts to connect through first, in order, like ssh -J: [user@]host[:port]. Each is checked against known_hosts and uses the same key.",
				},
				"ssh_config_file": {
					Type:        cty.String,
					Optional:    true,
					Description: "An OpenSSH config file, such as ~/.ssh/config, to read HostName, User, Port, IdentityFile, ProxyJump and UserKnownHostsFile from, with host as the Host alias. Anything set in this block wins. Nothing is read unless this is set.",
				},
				"private_key_file": {Type: cty.String, Optional: true, Description: "Path to a private key. Defaults to the SSH agent."},
				"host_key":         {Type: cty.String, Optional: true, Description: "Pinned host public key, in authorized_keys format."},
				"known_hosts_file": {Type: cty.String, Optional: true, Description: "known_hosts file to verify the host against. Defaults to ~/.ssh/known_hosts."},
				"become":           {Type: cty.Bool, Optional: true, Description: "Run commands as root through sudo."},
				"agent": {
					Type:        cty.Bool,
					Optional:    true,
					Description: "Run commands through the conn3x agent: a small program conn3x copies to the host and keeps running for the whole run, so each command costs one round trip instead of a new SSH session. An apply uploads it to ~/.cache/conn3x, checked by sha256; a plan only uses a copy already there. Hosts that can't run it fall back to plain shell commands. Not yet used with become. Overrides the CONN3X_AGENT environment variable: on, off, or require, which fails an apply rather than fall back to the shell. Defaults to off.",
				},
				"timeout": {
					Type:        cty.String,
					Optional:    true,
					Description: "How long to keep trying while the host isn't answering yet, such as a machine that is still booting. Defaults to \"3m\".",
				},
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
	client   *ssh.Client
	runner   modules.Runner
	useAgent bool
	require  bool // CONN3X_AGENT=require: an apply fails rather than use the shell
	host     string // for log messages

	mu        sync.Mutex
	agent     *agent.Client
	tried     [2]bool // attach tried without and with upload
	attachErr error   // why a required agent couldn't start
}

// Run sends cmd to the agent once one is attached, and through the shell
// otherwise. A command the agent fails to answer is never retried in the
// shell: it may already have run.
func (h *hostConn) Run(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	h.mu.Lock()
	a := h.agent
	h.mu.Unlock()
	if a != nil {
		return a.Run(ctx, cmd, stdin)
	}
	return h.runner.Run(ctx, cmd, stdin)
}

// attach starts the agent when this connection wants one, at most once
// without upload and once with it. When it can't, commands stay on the
// shell, unless the agent is required and this is an apply.
func (h *hostConn) attach(ctx context.Context, upload bool) error {
	if !h.useAgent {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	i := 0
	if upload {
		i = 1
	}
	if h.agent != nil {
		return nil
	}
	if h.tried[i] {
		return h.attachErr
	}
	h.tried[i] = true
	a, err := agent.Attach(ctx, h.client, agent.Options{Upload: upload, Version: version.Version, Payload: agentPayload})
	switch {
	case err == nil:
		h.agent = a
	case upload && h.require:
		h.attachErr = fmt.Errorf("CONN3X_AGENT=require, but the conn3x agent can't run on %s: %w", h.host, err)
		return h.attachErr
	case upload:
		log.Printf("[WARN] conn3x: running shell commands on %s: %v", h.host, err)
	default:
		log.Printf("[INFO] conn3x: running shell commands on %s until an apply: %v", h.host, err)
	}
	return nil
}

// alive reports whether the connection, and its agent if it has one,
// still work.
func (h *hostConn) alive() bool {
	h.mu.Lock()
	a := h.agent
	h.mu.Unlock()
	if a != nil && a.Err() != nil {
		return false
	}
	return h.client.Alive()
}

// Close returns the connection to the pool; it stays open for the run.
func (h *hostConn) Close() error { return nil }

const defaultConnectWait = 3 * time.Minute

type pooledConn struct {
	ready chan struct{} // closed once the dial finished
	conn  *hostConn
	err   error
}

var pool = struct {
	sync.Mutex
	conns map[string]*pooledConn
}{conns: map[string]*pooledConn{}}

// defaultAgent is whether hosts run commands through the agent when
// neither the agent attribute nor CONN3X_AGENT says.
const defaultAgent = false

// wantAgent reads the agent attribute, then CONN3X_AGENT, then the default.
// CONN3X_AGENT=require is "on" where a host that can't run the agent fails
// the apply instead of falling back to the shell; tests use it to prove
// the agent ran. It also applies where the attribute is true.
func wantAgent(conn cty.Value) (use, require bool) {
	env := strings.ToLower(os.Getenv("CONN3X_AGENT"))
	if v := optional(conn, "agent"); !v.IsNull() && v.IsKnown() {
		return v.True(), v.True() && env == "require"
	}
	switch env {
	case "on":
		return true, false
	case "require":
		return true, true
	case "off":
		return false, false
	case "":
	default:
		log.Printf("[WARN] conn3x: CONN3X_AGENT=%q is not on, off or require; ignoring it", env)
	}
	return defaultAgent, false
}

// dialConnection returns a connection to the host an ssh block describes,
// reusing an open one when it is still alive. For reads: it uses an agent
// already cached on the host but never uploads one.
func dialConnection(ctx context.Context, conn cty.Value) (*hostConn, error) {
	return dial(ctx, conn, false)
}

// dialForApply is dialConnection for applies, which may upload the agent.
func dialForApply(ctx context.Context, conn cty.Value) (*hostConn, error) {
	return dial(ctx, conn, true)
}

func dial(ctx context.Context, conn cty.Value, upload bool) (*hostConn, error) {
	h, err := pooled(ctx, conn)
	if err != nil {
		return nil, err
	}
	if err := h.attach(ctx, upload); err != nil {
		return nil, err
	}
	return h, nil
}

func pooled(ctx context.Context, conn cty.Value) (*hostConn, error) {
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
	// Under sudo the shell stays in charge until the agent can become root.
	useAgent, require := wantAgent(conn)
	useAgent = useAgent && !useSudo
	key := poolKey(cfg, useSudo, password, useAgent, require)

	pool.Lock()
	entry, ok := pool.conns[key]
	if ok {
		pool.Unlock()
		<-entry.ready
		if entry.err == nil && entry.conn.alive() {
			return entry.conn, nil
		}
		pool.Lock()
		// Another caller may already have replaced the dead entry.
		if pool.conns[key] == entry {
			delete(pool.conns, key)
			if entry.err == nil {
				_ = entry.conn.client.Close() // its agent may have died alone
			}
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

	wait := defaultConnectWait
	if v := stringOr(conn.GetAttr("timeout"), ""); v != "" {
		if wait, err = time.ParseDuration(v); err != nil {
			wait = defaultConnectWait
		}
	}
	client, err := ssh.DialWait(ctx, cfg, wait)
	if err != nil {
		entry.err = err
		pool.Lock()
		delete(pool.conns, key) // let the next caller retry
		pool.Unlock()
		close(entry.ready)
		return nil, err
	}
	h := &hostConn{client: client, runner: client, useAgent: useAgent, require: require, host: cfg.Host}
	if useSudo {
		h.runner = &ssh.Become{Client: client, Password: password}
	}
	entry.conn = h
	close(entry.ready)
	return h, nil
}

func poolKey(cfg ssh.Config, become bool, password []byte, useAgent, require bool) string {
	sum := sha256.New()
	for _, part := range [][]byte{
		[]byte(cfg.Host), []byte(strconv.Itoa(cfg.Port)), []byte(cfg.User), cfg.PrivateKey,
		[]byte(cfg.HostKey), []byte(cfg.KnownHostsFile), []byte(strconv.FormatBool(become)), password,
		[]byte(fmt.Sprint(cfg.Jumps)), // the same host through another bastion is another connection
		[]byte(strconv.FormatBool(useAgent)), []byte(strconv.FormatBool(require)),
	} {
		sum.Write(part)
		sum.Write([]byte{0})
	}
	return hex.EncodeToString(sum.Sum(nil))
}

// optional reads an attribute added after v0.1, which older values lack.
func optional(v cty.Value, name string) cty.Value {
	if !v.Type().HasAttribute(name) {
		return cty.NullVal(cty.DynamicPseudoType)
	}
	return v.GetAttr(name)
}

func sshConfig(conn cty.Value) (ssh.Config, error) {
	if conn.IsNull() || !conn.IsWhollyKnown() {
		return ssh.Config{}, fmt.Errorf("the ssh block is not known yet")
	}
	cfg := ssh.Config{
		Host:           conn.GetAttr("host").AsString(),
		User:           stringOr(conn.GetAttr("user"), ""),
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
	keyFile := expandHome(stringOr(conn.GetAttr("private_key_file"), ""))
	var jumps []string
	explicitJumps := !optional(conn, "jump_hosts").IsNull()
	if explicitJumps {
		for _, j := range optional(conn, "jump_hosts").AsValueSlice() {
			jumps = append(jumps, j.AsString())
		}
	}

	// An OpenSSH config only fills in what the block leaves out.
	if file := stringOr(optional(conn, "ssh_config_file"), ""); file != "" {
		f, err := os.Open(expandHome(file))
		if err != nil {
			return ssh.Config{}, fmt.Errorf("reading ssh_config_file: %w", err)
		}
		parsed, err := sshconfig.Decode(f)
		f.Close()
		if err != nil {
			return ssh.Config{}, fmt.Errorf("reading ssh_config_file: %w", err)
		}
		get := func(key string) string { v, _ := parsed.Get(cfg.Host, key); return v }
		if cfg.User == "" {
			cfg.User = get("User")
		}
		if cfg.Port == 0 {
			if p := get("Port"); p != "" {
				n, err := strconv.Atoi(p)
				if err != nil || n < 1 || n > 65535 {
					return ssh.Config{}, fmt.Errorf("ssh_config_file: Port %q for %s is not a port", p, cfg.Host)
				}
				cfg.Port = n
			}
		}
		if keyFile == "" {
			keyFile = expandHome(get("IdentityFile"))
		}
		if cfg.KnownHostsFile == "" {
			if kh := strings.Fields(get("UserKnownHostsFile")); len(kh) > 0 {
				cfg.KnownHostsFile = expandHome(kh[0])
			}
		}
		if pj := get("ProxyJump"); !explicitJumps && pj != "" && pj != "none" {
			jumps = strings.Split(pj, ",")
		}
		if name := get("HostName"); name != "" {
			cfg.Host = name
		}
	}
	if cfg.User == "" {
		return ssh.Config{}, fmt.Errorf("the ssh block needs a user, or an ssh_config_file that sets User for %s", cfg.Host)
	}
	for _, j := range jumps {
		jump, err := ssh.ParseJump(strings.TrimSpace(j))
		if err != nil {
			return ssh.Config{}, err
		}
		cfg.Jumps = append(cfg.Jumps, jump)
	}
	if keyFile != "" {
		key, err := os.ReadFile(keyFile)
		if err != nil {
			return ssh.Config{}, fmt.Errorf("reading private key %s: %w", keyFile, err)
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

// validateSSH checks the ssh block settings every resource shares.
func validateSSH(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.Type().IsObjectType() || !cfg.Type().HasAttribute("ssh") {
		return diags
	}
	conn := cfg.GetAttr("ssh")
	if conn.IsNull() || !conn.IsKnown() {
		return diags
	}
	if v := conn.GetAttr("timeout"); known(v) {
		if d, err := time.ParseDuration(v.AsString()); err != nil || d < 0 {
			diags = diags.Append(tfdiags.AttributeValue(tfdiags.Error, "Invalid ssh timeout",
				fmt.Sprintf("timeout must be a duration such as \"90s\" or \"5m\", not %q.", v.AsString()),
				cty.GetAttrPath("ssh").GetAttr("timeout")))
		}
	}
	return diags
}

// planID is a host resource's id: the host, its port when that isn't 22, then
// parts. The port keeps hosts behind one address apart. Ids in state written
// without it stay as they are, so upgrading plans no change.
func planID(req providers.PlanResourceChangeRequest, parts ...string) cty.Value {
	ssh := req.ProposedNewState.GetAttr("ssh")
	host, port := ssh.GetAttr("host"), ssh.GetAttr("port")
	if !host.IsKnown() || !port.IsKnown() {
		return cty.UnknownVal(cty.String)
	}
	legacy := strings.Join(append([]string{host.AsString()}, parts...), ":")
	id := strings.Join(append([]string{hostPort(ssh)}, parts...), ":")
	if !req.PriorState.IsNull() {
		if prior := req.PriorState.GetAttr("id"); prior.IsKnown() && prior.RawEquals(cty.StringVal(legacy)) {
			return prior
		}
	}
	return cty.StringVal(id)
}

// hostPort names a known ssh block's host: the address, plus the port when it isn't 22.
func hostPort(ssh cty.Value) string {
	if port := ssh.GetAttr("port"); !port.IsNull() && !port.RawEquals(cty.NumberIntVal(22)) {
		return ssh.GetAttr("host").AsString() + ":" + port.AsBigFloat().Text('f', 0)
	}
	return ssh.GetAttr("host").AsString()
}

// agentPayload is where attach gets the agent; tests swap it.
var agentPayload = agent.Embedded
