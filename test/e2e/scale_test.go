// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

type scaleHost struct{ Name, Port string }

// scalePortBase is the first port the hosts' sshd listen on.
const scalePortBase = 22200

type scaleVars struct {
	Hosts           []scaleHost
	Key, KnownHosts string
}

// TestScalePlan times apply and plan for a five-step circuit on many hosts,
// for #524. It runs only with CONN3X_SCALE set to host counts, such as
// "50,200", and appends a JSON line per count to CONN3X_SCALE_OUT if set.
// The hosts are sshd-only containers (test/images/scale), so hundreds fit
// on one machine; they measure Conn3x and SSH, not a real host's disk.
func TestScalePlan(t *testing.T) {
	counts := os.Getenv("CONN3X_SCALE")
	if counts == "" {
		t.Skip("set CONN3X_SCALE to host counts, such as 50,200")
	}
	_, here, _, _ := runtime.Caller(0)
	run(t, "podman", "build", "-q", "-t", "localhost/conn3x-scale", filepath.Join(filepath.Dir(here), "..", "images", "scale"))
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	signer, _ := gossh.NewSignerFromKey(priv)
	pub := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(signer.PublicKey())))

	for _, c := range strings.Split(counts, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(c))
		if err != nil || n < 1 {
			t.Fatalf("CONN3X_SCALE: %q isn't a host count", c)
		}
		t.Run(fmt.Sprintf("%d_hosts", n), func(t *testing.T) {
			hosts := startScaleHosts(t, n, pub)
			known := scaleKnownHosts(t, hosts)
			w := newWorkdir(t, "scale")
			w.writeAs("main.circuit.hcl", scaleVars{Hosts: hosts, Key: keyFile, KnownHosts: known})
			w.mustConn3x("init", "-no-color")
			timed := func(args ...string) time.Duration {
				start := time.Now()
				w.mustConn3x(args...)
				return time.Since(start).Round(time.Millisecond)
			}
			res := map[string]any{"hosts": n, "steps": 5 * n, "go": runtime.Version(), "cpus": runtime.NumCPU()}
			res["apply"] = timed("apply", "-auto-approve", "-no-color").Seconds()
			res["plan"] = timed("plan", "-no-color").Seconds()
			res["plan_parallelism_50"] = timed("plan", "-no-color", "-parallelism=50").Seconds()
			res["plan_refresh_false"] = timed("plan", "-no-color", "-refresh=false").Seconds()
			line, _ := json.Marshal(res)
			t.Logf("%s", line)
			if out := os.Getenv("CONN3X_SCALE_OUT"); out != "" {
				f, err := os.OpenFile(out, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				fmt.Fprintf(f, "%s\n", line)
			}
		})
	}
}

// startScaleHosts starts n sshd containers, 16 at a time, and waits until
// each takes connections.
func startScaleHosts(t *testing.T, n int, pub string) []scaleHost {
	t.Helper()
	hosts := make([]scaleHost, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			// The host's network, with a port each: a published port costs
			// rootless Podman a forwarding process per container, and those
			// run out long before 500.
			port := strconv.Itoa(scalePortBase + i)
			out, err := exec.Command("podman", "run", "-d", "--rm", "--network=host", "-e", "PORT="+port, "-e", "AUTHORIZED_KEY="+pub, "localhost/conn3x-scale").CombinedOutput()
			if err != nil {
				errs[i] = fmt.Errorf("podman run: %w: %s", err, out)
				return
			}
			id := strings.TrimSpace(string(out))
			t.Cleanup(func() { _ = exec.Command("podman", "rm", "-f", id).Run() })
			hosts[i] = scaleHost{Name: fmt.Sprintf("h%04d", i), Port: port}
			for range 100 {
				if c, err := net.DialTimeout("tcp", "127.0.0.1:"+hosts[i].Port, time.Second); err == nil {
					buf := make([]byte, 4)
					_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
					_, err = c.Read(buf)
					c.Close()
					if err == nil && string(buf) == "SSH-" {
						return
					}
				}
				time.Sleep(100 * time.Millisecond)
			}
			errs[i] = fmt.Errorf("sshd on port %s never answered", hosts[i].Port)
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	return hosts
}

// scaleKnownHosts writes one known_hosts line per port. The image gives
// every container the same host key, so one scan does for all of them.
func scaleKnownHosts(t *testing.T, hosts []scaleHost) string {
	t.Helper()
	scan := run(t, "ssh-keyscan", "-t", "ed25519", "-p", hosts[0].Port, "127.0.0.1")
	var key string
	for _, l := range strings.Split(scan, "\n") {
		if _, k, ok := strings.Cut(strings.TrimSpace(l), " "); ok && strings.HasPrefix(k, "ssh-ed25519 ") {
			key = k
		}
	}
	if key == "" {
		t.Fatalf("ssh-keyscan: %q", scan)
	}
	var b strings.Builder
	for _, h := range hosts {
		fmt.Fprintf(&b, "[127.0.0.1]:%s %s\n", h.Port, key)
	}
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
