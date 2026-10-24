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
	token := os.Getenv("DIGITALOCEAN_TOKEN")
	if token == "" {
		t.Skip("DIGITALOCEAN_TOKEN is not set")
	}
	api := &doapi.Client{Token: token}

	_, here, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(here), "..", "..")
	dir := t.TempDir()
	bin := filepath.Join(dir, "conn3x")
	build := exec.Command("bash", "scripts/build-conn3x.sh", bin)
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building conn3x: %v\n%s", err, out)
	}

	runBytes := make([]byte, 4)
	_, _ = rand.Read(runBytes)
	runID := hex.EncodeToString(runBytes)

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	sshPub, _ := gossh.NewPublicKey(pub)

	pwBytes := make([]byte, 12)
	_, _ = rand.Read(pwBytes)
	sudoPassword := "C3x-" + hex.EncodeToString(pwBytes)
	pwFile := filepath.Join(dir, "sudo-password")
	if err := os.WriteFile(pwFile, []byte(sudoPassword+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tpl := template.Must(template.ParseFiles(filepath.Join(filepath.Dir(here), "testdata", "main.tf.tmpl")))
	var cfg bytes.Buffer
	if err := tpl.Execute(&cfg, vars{
		RunID:          runID,
		Image:          "rockylinux-10-x64",
		PublicKey:      strings.TrimSpace(string(gossh.MarshalAuthorizedKey(sshPub))),
		PrivateKeyFile:   keyFile,
		SudoPassword:     sudoPassword,
		SudoPasswordFile: pwFile,
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), cfg.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	conn3x := func(args ...string) (string, error) {
		cmd := exec.Command(bin, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "TF_IN_AUTOMATION=1", "CHECKPOINT_DISABLE=1")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	must := func(args ...string) string {
		t.Helper()
		out, err := conn3x(args...)
		if err != nil {
			t.Fatalf("conn3x %v: %v\n%s", args, err, out)
		}
		return out
	}

	// Whatever happens, leave nothing behind: destroy through Conn3x, then
	// delete this run's droplet and key through the API in case that failed.
	t.Cleanup(func() {
		if out, err := conn3x("destroy", "-auto-approve", "-no-color"); err != nil {
			t.Logf("conn3x destroy failed, falling back to the API: %v\n%s", err, out)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := api.DeleteRun(ctx, runID); err != nil {
			t.Errorf("cleaning up run %s: %v", runID, err)
		}
	})

	must("init", "-no-color")
	plan := must("plan", "-no-color")
	for _, want := range []string{
		"digitalocean_droplet.web will be created",
		`conn3x_package.web__nginx["web1"] will be created`,
		`conn3x_file.web__page["web1"] will be created`,
		`conn3x_service.web__running["web1"] will be created`,
		`conn3x_file.sudo_check__marker["web1"] will be created`,
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

	want := "<h1>Hello from web1, set up by Conn3x</h1>\n"
	var got string
	for deadline := time.Now().Add(2 * time.Minute); time.Now().Before(deadline); time.Sleep(5 * time.Second) {
		resp, err := http.Get("http://" + ip + "/")
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if got = string(body); got == want {
				break
			}
		}
	}
	if got != want {
		t.Fatalf("http://%s/ served %q, want %q", ip, got, want)
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
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	stat, err := session.Output("stat -c '%U %a' /etc/conn3x-sudo-check && cat /etc/conn3x-sudo-check")
	if err != nil {
		t.Fatalf("checking the sudo marker: %v", err)
	}
	if got := string(stat); got != "root 600\nwritten through sudo\n" {
		t.Fatalf("sudo marker = %q", got)
	}

	if out := must("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply is not empty:\n%s", out)
	}
}
