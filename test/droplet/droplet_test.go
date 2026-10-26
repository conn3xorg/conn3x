// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build droplet

// Package droplet runs Conn3x against real DigitalOcean droplets: one plan
// that creates a droplet and configures it. It needs DIGITALOCEAN_TOKEN and
// creates billable resources, every one tagged or named conn3x-ci and
// deleted when the test ends.
//
//	DIGITALOCEAN_TOKEN=... go test -tags droplet -timeout 30m ./test/droplet/
package droplet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"text/template"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/opentofu/opentofu/test/droplet/doapi"
)

type vars struct {
	RunID, Image, PublicKey, PrivateKeyFile string
	SudoPassword, SudoPasswordFile          string
}

func TestDropletAndCircuitInOnePlan(t *testing.T) {
	r := newRun(t)
	dir := r.dir
	r.render(t, "main.tf.tmpl", vars{
		RunID:            r.id,
		Image:            "rockylinux-10-x64",
		PublicKey:        r.publicKey,
		PrivateKeyFile:   r.keyFile,
		SudoPassword:     r.sudoPassword,
		SudoPasswordFile: r.pwFile,
	}, filepath.Join(dir, "main.tf"))

	conn3x := func(args ...string) (string, error) { return r.conn3x(dir, nil, args...) }
	must := func(args ...string) string {
		t.Helper()
		return r.must(t, dir, nil, args...)
	}
	priv := r.priv
	r.cleanup(t, dir)

	must("init", "-no-color")
	plan := must("plan", "-no-color")
	for _, want := range []string{
		"digitalocean_droplet.web will be created",
		`conn3x_package.web__nginx["web1"] will be created`,
		`conn3x_file.web__page["web1"] will be created`,
		`conn3x_service.web__running["web1"] will be created`,
		`conn3x_file.sudo_check__marker["web1"] will be created`,
		`conn3x_sysctl.web__forwarding["web1"] will be created`,
		`conn3x_hostname.web__name["web1"] will be created`,
		`conn3x_firewalld.web__http["web1"] will be created`,
		`conn3x_mount.web__scratch["web1"] will be created`,
		`conn3x_selinux_boolean.web__proxy["web1"] will be created`,
		`conn3x_selinux_fcontext.web__content_label["web1"] will be created`,
		`conn3x_ufw_rule.edge__http["edge1"] will be created`,
		`conn3x_reboot.edge__reboot["edge1"] will be created`,
		"host             = (known after apply)",
		"Conn3x will perform the following actions",
	} {
		if !strings.Contains(plan, want) {
			t.Fatalf("plan is missing %q:\n%s", want, plan)
		}
	}
	if strings.Contains(plan, "OpenTofu") {
		t.Fatalf("plan names OpenTofu:\n%s", plan)
	}

	must("apply", "-auto-approve", "-no-color")
	ip := strings.TrimSpace(must("output", "-raw", "ip"))

	// Both pages come through a firewall: firewalld on web, ufw on edge.
	want := "<h1>Hello from web1, set up by Conn3x</h1>\n"
	if got := fetch("http://"+ip+"/", want); got != want {
		t.Fatalf("http://%s/ served %q, want %q", ip, got, want)
	}
	edgeIP := strings.TrimSpace(must("output", "-raw", "edge_ip"))
	if got := fetch("http://"+edgeIP+"/", "nginx"); !strings.Contains(got, "nginx") {
		t.Fatalf("http://%s/ through ufw served %q", edgeIP, got)
	}

	// The sudo circuit wrote a root-owned file as deploy, through sudo with
	// a password. Check it as root over our own SSH connection.
	hostKey, _, _, _, err := gossh.ParseAuthorizedKey([]byte(must("output", "-raw", "host_key")))
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := gossh.NewSignerFromKey(priv)
	client, err := gossh.Dial("tcp", ip+":22", &gossh.ClientConfig{
		User:            "root",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.FixedHostKey(hostKey),
		Timeout:         30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	run := func(cmd string) string { t.Helper(); return runOn(t, client, cmd) }
	if got := run("stat -c '%U %a' /etc/conn3x-sudo-check && cat /etc/conn3x-sudo-check"); got != "root 600\nwritten through sudo\n" {
		t.Fatalf("sudo marker = %q", got)
	}
	if got := run("sysctl -n net.ipv4.ip_forward net.ipv4.ip_local_port_range"); got != "1\n20000\t60999\n" {
		t.Fatalf("running sysctl values = %q", got)
	}
	if got := run("cat /etc/sysctl.d/90-conn3x-net.ipv4.ip_forward.conf"); got != "# Managed by Conn3x.\nnet.ipv4.ip_forward = 1\n" {
		t.Fatalf("sysctl drop-in = %q", got)
	}
	if got := run("hostname; cat /etc/hostname"); got != "web1.conn3x-ci.internal\nweb1.conn3x-ci.internal\n" {
		t.Fatalf("hostname = %q", got)
	}

	if got := run("echo $(cat /sys/fs/selinux/booleans/httpd_can_network_connect); semanage boolean -l -C | grep -c '^httpd_can_network_connect '"); got != "1 1\n1\n" {
		t.Fatalf("httpd_can_network_connect, running and persistent = %q", got)
	}
	if got := run("stat -c %C /srv/conn3x"); !strings.Contains(got, ":httpd_sys_content_t:") {
		t.Fatalf("/srv/conn3x label = %q", got)
	}
	if got := run("findmnt -n -M /mnt/conn3x-scratch -o FSTYPE,OPTIONS; grep ' /mnt/conn3x-scratch ' /etc/fstab"); !strings.Contains(got, "size=16384k") || !strings.Contains(got, "tmpfs /mnt/conn3x-scratch tmpfs size=16m,mode=0755 0 0") {
		t.Fatalf("scratch mount:\n%s", got)
	}
	if got := run("firewall-cmd --list-services; firewall-cmd --permanent --list-services"); strings.Count(got, "http") != 2 {
		t.Fatalf("firewalld services = %q", got)
	}

	edge, err := gossh.Dial("tcp", edgeIP+":22", &gossh.ClientConfig{
		User:            "root",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.FixedHostKey(hostKey),
		Timeout:         30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer edge.Close()
	if got := runOn(t, edge, "test -e /run/conn3x-before-reboot && echo still there || echo gone"); got != "gone\n" {
		t.Fatalf("edge did not reboot: marker %s", got)
	}
	if got := runOn(t, edge, "ufw status"); !strings.Contains(got, "Status: active") || !strings.Contains(got, "80/tcp") {
		t.Fatalf("ufw status:\n%s", got)
	}

	if out := must("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply is not empty:\n%s", out)
	}
	if out, err := conn3x("drift", "-no-color"); err != nil || !strings.Contains(out, "No drift") {
		t.Fatalf("drift after apply: %v\n%s", err, out)
	}
}

// fetch polls url until its body contains want or two minutes pass, and
// returns the last body it saw.
// run is one test run: a conn3x binary, a key pair and a sudo password,
// and a run ID that names everything it creates in DigitalOcean.
type run struct {
	api                  *doapi.Client
	here, dir, bin, id   string
	keyFile, publicKey   string
	priv                 ed25519.PrivateKey
	sudoPassword, pwFile string
}

// newRun builds conn3x and makes the run's keys, or skips the test
// without DIGITALOCEAN_TOKEN.
func newRun(t *testing.T) *run {
	t.Helper()
	token := os.Getenv("DIGITALOCEAN_TOKEN")
	if token == "" {
		t.Skip("DIGITALOCEAN_TOKEN is not set")
	}
	_, here, _, _ := runtime.Caller(0)
	r := &run{api: &doapi.Client{Token: token}, here: filepath.Dir(here), dir: t.TempDir()}
	r.bin = filepath.Join(r.dir, "conn3x")
	build := exec.Command("bash", "scripts/build-conn3x.sh", r.bin)
	build.Dir = filepath.Join(r.here, "..", "..")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building conn3x: %v\n%s", err, out)
	}

	runBytes := make([]byte, 4)
	_, _ = rand.Read(runBytes)
	r.id = hex.EncodeToString(runBytes)

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	r.priv = priv
	r.keyFile = filepath.Join(r.dir, "id_ed25519")
	if err := os.WriteFile(r.keyFile, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	sshPub, _ := gossh.NewPublicKey(pub)
	r.publicKey = strings.TrimSpace(string(gossh.MarshalAuthorizedKey(sshPub)))

	pwBytes := make([]byte, 12)
	_, _ = rand.Read(pwBytes)
	r.sudoPassword = "C3x-" + hex.EncodeToString(pwBytes)
	r.pwFile = filepath.Join(r.dir, "sudo-password")
	if err := os.WriteFile(r.pwFile, []byte(r.sudoPassword+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return r
}

// render executes the template testdata/name with data into out.
func (r *run) render(t *testing.T, name string, data any, out string) {
	t.Helper()
	tpl := template.Must(template.ParseFiles(filepath.Join(r.here, "testdata", name)))
	var cfg bytes.Buffer
	if err := tpl.Execute(&cfg, data); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, cfg.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// conn3x runs the binary in dir with env added.
func (r *run) conn3x(dir string, env []string, args ...string) (string, error) {
	cmd := exec.Command(r.bin, args...)
	cmd.Dir = dir
	cmd.Env = append(append(os.Environ(), "TF_IN_AUTOMATION=1", "CHECKPOINT_DISABLE=1"), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (r *run) must(t *testing.T, dir string, env []string, args ...string) string {
	t.Helper()
	out, err := r.conn3x(dir, env, args...)
	if err != nil {
		t.Fatalf("conn3x %v: %v\n%s", args, err, out)
	}
	return out
}

// cleanup destroys what the configuration in dir made when the test ends,
// however it ends, then deletes the run's droplets and key through the
// API in case that failed.
func (r *run) cleanup(t *testing.T, dir string) {
	t.Cleanup(func() {
		if out, err := r.conn3x(dir, nil, "destroy", "-auto-approve", "-no-color"); err != nil {
			t.Logf("conn3x destroy failed, falling back to the API: %v\n%s", err, out)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := r.api.DeleteRun(ctx, r.id); err != nil {
			t.Errorf("cleaning up run %s: %v", r.id, err)
		}
	})
}

func fetch(url, want string) string {
	var got string
	for deadline := time.Now().Add(2 * time.Minute); time.Now().Before(deadline); time.Sleep(5 * time.Second) {
		resp, err := http.Get(url)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if got = string(body); strings.Contains(got, want) {
				break
			}
		}
	}
	return got
}

func runOn(t *testing.T, client *gossh.Client, cmd string) string {
	t.Helper()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	out, err := session.Output(cmd)
	if err != nil {
		t.Fatalf("%s: %v", cmd, err)
	}
	return string(out)
}
