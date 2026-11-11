// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"crypto/ed25519"
	"os"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

type exclusiveKeyVars struct {
	Port, KeyFile, KnownHosts string
	Present                   bool
	User, Keys                string
}

func newKeyLine(t *testing.T, comment string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	k, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(gossh.MarshalAuthorizedKey(k))) + " " + comment
}

// heredoc indents keys for an HCL <<-EOT.
func heredoc(keys ...string) string {
	return "        " + strings.Join(keys, "\n        ")
}

// An exclusive authorized_key step makes the user's authorized_keys exactly
// its keys: a key added by hand is named in the plan's warning and removed.
// Making root's keys exclusive without the key Conn3x logs in with is
// refused, and removing the step leaves the file.
func TestAuthorizedKeyExclusive(t *testing.T) {
	for _, image := range []string{"rocky10", "ubuntu2404"} {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			a, b, extra := newKeyLine(t, "a@listed"), newKeyLine(t, "b@listed"), newKeyLine(t, "x@by-hand")
			h.exec("", "sh", "-c", "useradd -m deploy && install -d -m 700 -o deploy -g deploy ~deploy/.ssh && printf '%s\\n%s\\n' '"+extra+"' '"+a+"' > ~deploy/.ssh/authorized_keys && chown deploy:deploy ~deploy/.ssh/authorized_keys && chmod 600 ~deploy/.ssh/authorized_keys")
			keysOf := func(user string) string {
				return h.exec("", "sh", "-c", "cat ~"+user+"/.ssh/authorized_keys")
			}

			w := newWorkdir(t, "authorized_key_exclusive")
			vars := exclusiveKeyVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, Present: true, User: "deploy", Keys: heredoc(a, b)}
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := keysOf("deploy"); got != a+"\n"+b+"\n" {
				t.Fatalf("deploy's keys after the apply:\n%s", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			// A key added by hand is named on the next plan, and removed.
			h.exec("", "sh", "-c", "printf '%s\\n' '"+extra+"' >> ~deploy/.ssh/authorized_keys")
			out := w.mustConn3x("plan", "-no-color")
			if !strings.Contains(out, "x@by-hand (ssh-ed25519 SHA256:") || !strings.Contains(out, "1 to change") {
				t.Fatalf("plan with a key added by hand:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := keysOf("deploy"); strings.Contains(got, "x@by-hand") {
				t.Fatalf("the key added by hand is still there:\n%s", got)
			}
			state := w.mustConn3x("state", "pull")
			if strings.Contains(state, "x@by-hand") {
				t.Fatalf("state keeps a comment of an unlisted key:\n%s", state)
			}

			// Root is who Conn3x logs in as: a list without its key is refused.
			before := keysOf("root")
			vars.User, vars.Keys = "root", heredoc(a)
			w.writeAs("main.circuit.hcl", vars)
			if out, code := w.conn3x("apply", "-auto-approve", "-no-color"); code == 0 || !strings.Contains(out, "the next run couldn't log in") {
				t.Fatalf("making root's keys exclusive without the login key (exit %d):\n%s", code, out)
			}
			if got := keysOf("root"); got != before {
				t.Fatalf("root's keys changed after the refusal:\n%s", got)
			}

			// With the login key listed, root's keys can be exclusive, and the
			// next run still logs in.
			pemKey, err := os.ReadFile(h.keyFile)
			if err != nil {
				t.Fatal(err)
			}
			signer, err := gossh.ParsePrivateKey(pemKey)
			if err != nil {
				t.Fatal(err)
			}
			login := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(signer.PublicKey()))) + " conn3x-login"
			h.exec("", "sh", "-c", "printf '%s\\n' '"+extra+"' >> ~root/.ssh/authorized_keys")
			vars.Keys = heredoc(login, a)
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := keysOf("root"); strings.Contains(got, "x@by-hand") || !strings.Contains(got, strings.Fields(login)[1]) {
				t.Fatalf("root's keys with the login key listed:\n%s", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after making root's keys exclusive:\n%s", out)
			}

			// Removing the step leaves deploy's file as it was.
			vars = exclusiveKeyVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts}
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := keysOf("deploy"); got != a+"\n"+b+"\n" {
				t.Fatalf("deploy's keys after removing the step:\n%s", got)
			}
		})
	}
}
