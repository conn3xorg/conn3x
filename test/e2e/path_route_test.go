// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type routeVars struct{ Port, KeyFile, KnownHosts, Step string }

const routeReset = `rm -rf /opt/guard && mkdir -m 0700 /opt/guard && echo original > /opt/guard/keep && chmod 0600 /opt/guard/keep`

// routeHost is a host with a user, alice, and a directory she has no access to.
func routeHost(t *testing.T, image string) (*host, func() string) {
	t.Helper()
	h := startHost(t, image)
	h.exec("", "sh", "-c", `useradd -m alice && chmod 0755 /home/alice`)
	h.exec("", "sh", "-c", routeReset)
	return h, func() string {
		t.Helper()
		return h.exec("", "sh", "-c", `stat -c '%n %u %g %a' /opt/guard /opt/guard/keep; ls -A /opt/guard; cat /opt/guard/keep`)
	}
}

func routeApply(t *testing.T, h *host, step string) (*workdir, string, int) {
	t.Helper()
	w := newWorkdir(t, "path_route")
	w.writeAs("main.circuit.hcl", routeVars{h.port, h.keyFile, h.knownHosts, step})
	w.mustConn3x("init", "-no-color")
	out, code := w.conn3x("apply", "-auto-approve", "-no-color")
	return w, out, code
}

// Whatever alice has done to her own home, steps on paths inside it leave
// everything outside it as it was.
func TestPathsInsideAUsersHome(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h, guard := routeHost(t, image)
			h.exec("", "sh", "-c", "tar -cf /tmp/src.tar -C /etc hostname")
			want := guard()
			for _, c := range []struct{ name, link, target, step string }{
				{"directory", "data", "/opt/guard", `directory {
      path  = "/home/alice/data"
      mode  = "0777"
      owner = "alice"
      group = "alice"
    }`},
				{"directory below", "d", "/opt/guard", `directory {
      path = "/home/alice/d/sub"
      mode = "0777"
    }`},
				{"file below", "conf", "/opt/guard", `file {
      path    = "/home/alice/conf/app.conf"
      content = "managed\n"
      owner   = "alice"
    }`},
				{"file at a directory link", "app.conf", "/opt/guard", `file {
      path    = "/home/alice/app.conf"
      content = "managed\n"
    }`},
				{"line", "l.conf", "/opt/guard/keep", `line {
      path = "/home/alice/l.conf"
      line = "managed"
    }`},
				{"block", "b.conf", "/opt/guard/keep", `block {
      path    = "/home/alice/b.conf"
      content = "managed"
    }`},
				{"ini", "i.ini", "/opt/guard/keep", `ini {
      path   = "/home/alice/i.ini"
      option = "key"
      value  = "managed"
    }`},
				{"replace", "r.conf", "/opt/guard/keep", `replace {
      path    = "/home/alice/r.conf"
      regexp  = "original"
      replace = "managed"
    }`},
				{"link", "ln", "/opt/guard", `link {
      path   = "/home/alice/ln/new"
      target = "/etc/hostname"
    }`},
				{"archive", "ar", "/opt/guard", `archive {
      src     = "/tmp/src.tar"
      dest    = "/home/alice/ar"
      creates = "/home/alice/ar/hostname"
    }`},
			} {
				t.Run(c.name, func(t *testing.T) {
					h.exec("", "sh", "-c", routeReset)
					h.exec("", "su", "alice", "-c", "ln -s "+c.target+" /home/alice/"+c.link)
					_, out, _ := routeApply(t, h, c.step)
					if got := guard(); got != want {
						t.Fatalf("outside the home changed:\n%s\nwas:\n%s\napply said:\n%s", got, want, out)
					}
				})
			}
		})
	}
}

// A read doesn't bring back what the user couldn't read themselves.
func TestReadsInsideAUsersHome(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h, _ := routeHost(t, image)
			w, out, code := routeApply(t, h, `file {
      path    = "/home/alice/r.conf"
      content = "managed\n"
      owner   = "alice"
    }`)
			if code != 0 {
				t.Fatalf("apply: %s", out)
			}
			h.exec("", "su", "alice", "-c", "ln -sf /opt/guard/keep /home/alice/r.conf")
			plan, _ := w.conn3x("plan", "-no-color")
			show, _ := w.conn3x("show", "-json")
			if strings.Contains(plan+show, "original") {
				t.Fatalf("the read returned a file out of reach:\n%s\n%s", plan, show)
			}
		})
	}
}

// The usual ways of using a user's or a service's own directory keep working,
// and what can't work says why.
func TestPathsOwnedByAUser(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h, _ := routeHost(t, image)
			check := func(p, want string) {
				t.Helper()
				if got := strings.TrimSpace(h.exec("", "stat", "-c", "%U:%G %a", p)); got != want {
					t.Fatalf("%s is %s, want %s", p, got, want)
				}
			}
			clean := func(w *workdir, out string, code int) {
				t.Helper()
				if code != 0 {
					t.Fatalf("apply:\n%s", out)
				}
				if plan := w.mustConn3x("plan", "-no-color"); !strings.Contains(plan, "No changes.") {
					t.Fatalf("plan after apply:\n%s", plan)
				}
			}

			w, out, code := routeApply(t, h, `directory {
      path  = "/home/alice/app/conf"
      mode  = "0750"
      owner = "alice"
      group = "alice"
    }`)
			clean(w, out, code)
			check("/home/alice/app/conf", "alice:alice 750")

			w, out, code = routeApply(t, h, `file {
      path    = "/home/alice/app/conf/a"
      content = "managed\n"
      mode    = "0640"
      owner   = "alice"
    }`)
			clean(w, out, code)
			check("/home/alice/app/conf/a", "alice:alice 640")

			w, out, code = routeApply(t, h, `line {
      path   = "/home/alice/app/conf/a"
      line   = "edited"
    }`)
			clean(w, out, code)

			// A link of her own to her own file is written through.
			h.exec("", "su", "alice", "-c", "ln -s app/conf/a /home/alice/own")
			w, out, code = routeApply(t, h, `line {
      path   = "/home/alice/own"
      line   = "through"
    }`)
			clean(w, out, code)
			if got := h.exec("", "tail", "-n", "1", "/home/alice/app/conf/a"); got != "through\n" {
				t.Fatalf("a = %q", got)
			}

			// A service's directory, with a group the service isn't in.
			h.exec("", "sh", "-c", "mkdir /etc/svc && chown alice:root /etc/svc && chmod 0750 /etc/svc")
			w, out, code = routeApply(t, h, `file {
      path    = "/etc/svc/conf"
      content = "managed\n"
      mode    = "0640"
      owner   = "alice"
      group   = "root"
    }`)
			clean(w, out, code)
			check("/etc/svc/conf", "alice:root 640")

			// Links root made, and a directory directly under root's own.
			h.exec("old\n", "sh", "-c", "cat > /etc/real.conf; ln -s real.conf /etc/rel.conf; ln -s /etc/real.conf /etc/abs.conf")
			for _, p := range []string{"rel", "abs"} {
				w, out, code = routeApply(t, h, `line {
      path = "/etc/`+p+`.conf"
      line = "`+p+`"
    }`)
				clean(w, out, code)
				if h.exec("", "sh", "-c", "test ! -L /etc/"+p+".conf && echo replaced || grep -c "+p+" /etc/real.conf") != "1\n" {
					t.Fatalf("%s.conf wasn't written through", p)
				}
			}

			// What a user can't do says so.
			_, out, code = routeApply(t, h, `file {
      path    = "/home/alice/rootfile"
      content = "x\n"
      owner   = "root"
    }`)
			if code == 0 || !strings.Contains(out, "can't give a file to root") || !strings.Contains(out, "Conn3x works there as alice") {
				t.Fatalf("root's file in alice's home, exit %d:\n%s", code, out)
			}

			// An edit that fails on a plain file doesn't call it a symlink.
			h.exec("", "sh", "-c", "echo a > /home/alice/rootline; chown root:root /home/alice/rootline; chmod 644 /home/alice/rootline")
			_, out, code = routeApply(t, h, `line {
      path = "/home/alice/rootline"
      line = "b"
    }`)
			if code == 0 || strings.Contains(out, "symlink") || !strings.Contains(out, "can't be written by alice") {
				t.Fatalf("root's file edited in alice's home, exit %d:\n%s", code, out)
			}
		})
	}
}
