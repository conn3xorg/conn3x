// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"os"
	"strings"
	"testing"
)

// An archive only ever fills its dest, however its entries are named.
func TestArchiveStaysInDest(t *testing.T) {
	var tarBuf, zipBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	if err := tw.WriteHeader(&tar.Header{Name: "../outside-tar", Typeflag: tar.TypeReg, Mode: 0o644, Size: 2}); err != nil {
		t.Fatal(err)
	}
	_, _ = tw.Write([]byte("x\n"))
	tw.Close()
	zw := zip.NewWriter(&zipBuf)
	if fw, err := zw.Create("../outside-zip"); err != nil {
		t.Fatal(err)
	} else {
		_, _ = fw.Write([]byte("x\n"))
	}
	zw.Close()
	var linkZip bytes.Buffer
	zw = zip.NewWriter(&linkZip)
	lh := &zip.FileHeader{Name: "l"}
	lh.SetMode(os.ModeSymlink | 0o777)
	for _, e := range []struct {
		h    *zip.FileHeader
		body string
	}{{lh, "/opt/guard"}, {&zip.FileHeader{Name: "l/new"}, "x\n"}, {&zip.FileHeader{Name: "done"}, "x\n"}} {
		fw, err := zw.CreateHeader(e.h)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fw.Write([]byte(e.body))
	}
	zw.Close()
	var linkBuf, ownBuf bytes.Buffer
	for _, b := range []struct {
		w     *bytes.Buffer
		items []tar.Header
	}{
		{&linkBuf, []tar.Header{
			{Name: "l", Typeflag: tar.TypeSymlink, Linkname: "/opt/guard", Mode: 0o777},
			{Name: "l/new", Typeflag: tar.TypeReg, Mode: 0o644, Size: 2},
			{Name: "done", Typeflag: tar.TypeReg, Mode: 0o644, Size: 2},
		}},
		{&ownBuf, []tar.Header{
			{Name: "./", Typeflag: tar.TypeDir, Mode: 0o777},
			{Name: "./f", Typeflag: tar.TypeReg, Mode: 0o644, Size: 2, Uid: 4242, Gid: 4242},
		}},
	} {
		tw := tar.NewWriter(b.w)
		for i := range b.items {
			e := b.items[i]
			if err := tw.WriteHeader(&e); err != nil {
				t.Fatal(err)
			}
			if e.Typeflag == tar.TypeReg {
				_, _ = tw.Write([]byte("x\n"))
			}
		}
		tw.Close()
	}

	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h, guard := routeHost(t, image)
			if rpmImage(image) {
				h.exec("", "dnf", "-q", "-y", "install", "unzip")
			} else {
				h.exec("", "sh", "-c", "apt-get -qq update && apt-get -qq -y install unzip")
			}
			want := guard()
			step := func(src, dest, creates string) string {
				return `archive {
      src     = "` + src + `"
      dest    = "` + dest + `"
      creates = "` + creates + `"
    }`
			}
			h.exec(tarBuf.String(), "sh", "-c", "cat > /tmp/a.tar")
			h.exec(zipBuf.String(), "sh", "-c", "cat > /tmp/a.zip")
			h.exec(linkBuf.String(), "sh", "-c", "cat > /tmp/l.tar")
			h.exec(ownBuf.String(), "sh", "-c", "cat > /tmp/o.tar")
			h.exec(linkZip.String(), "sh", "-c", "cat > /tmp/l.zip")

			for _, c := range [][2]string{{"/tmp/a.tar", "/opt/d1"}, {"/tmp/a.zip", "/opt/d2"}, {"/tmp/l.tar", "/opt/d3"}, {"/tmp/l.zip", "/opt/d5"}} {
				_, _, _ = routeApply(t, h, step(c[0], c[1], c[1]+"/done"))
				if got := h.exec("", "sh", "-c", "ls /opt | grep outside || true"); got != "" {
					t.Fatalf("%s left %s", c[0], got)
				}
				if got := guard(); got != want {
					t.Fatalf("%s changed what's outside dest:\n%s", c[0], got)
				}
			}

			h.exec("", "sh", "-c", "mkdir -m 0750 /opt/d4")
			if _, out, code := routeApply(t, h, step("/tmp/o.tar", "/opt/d4", "/opt/d4/f")); code != 0 {
				t.Fatalf("apply:\n%s", out)
			}
			if got := strings.TrimSpace(h.exec("", "stat", "-c", "%U %a", "/opt/d4")); got != "root 750" {
				t.Fatalf("dest is %s", got)
			}
			if got := strings.TrimSpace(h.exec("", "stat", "-c", "%u", "/opt/d4/f")); got != "0" {
				t.Fatalf("unpacked file has uid %s", got)
			}
		})
	}
}

// A checkout in a user's directory runs git as that user, whose settings in
// that directory are theirs to set.
func TestGitInAUsersDirectory(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h, _ := routeHost(t, image)
			if rpmImage(image) {
				h.exec("", "dnf", "-q", "-y", "install", "git-core")
			} else {
				h.exec("", "sh", "-c", "apt-get -qq update && apt-get -qq -y install git")
			}
			commit := strings.TrimSpace(h.exec("", "su", "alice", "-c", `set -e
cd /home/alice
git init -q src
cd src
git -c user.name=a -c user.email=a@example.com commit -q --allow-empty -m one
git rev-parse HEAD`))
			step := func(dest string) string {
				return `git {
      repo = "file:///home/alice/src"
      dest = "` + dest + `"
      ref  = "` + commit + `"
    }`
			}

			// Her own settings on a checkout of hers.
			h.exec("", "su", "alice", "-c", `set -e
git clone -q /home/alice/src /home/alice/co
printf '#!/bin/sh\nid -u > /tmp/git-ran-as\n' > /home/alice/hook
chmod +x /home/alice/hook
git -C /home/alice/co config core.fsmonitor /home/alice/hook
git -C /home/alice/co config core.sshCommand /home/alice/hook`)
			w, out, code := routeApply(t, h, step("/home/alice/co"))
			if code != 0 {
				t.Fatalf("apply:\n%s", out)
			}
			if got := h.exec("", "sh", "-c", "cat /tmp/git-ran-as 2>/dev/null || true"); strings.TrimSpace(got) == "0" {
				t.Fatal("a setting of hers ran as root")
			}
			if plan := w.mustConn3x("plan", "-no-color"); !strings.Contains(plan, "No changes.") {
				t.Fatalf("plan after apply:\n%s", plan)
			}

			// A new one of hers is hers; one of root's stays root's.
			if _, out, code := routeApply(t, h, step("/home/alice/new")); code != 0 {
				t.Fatalf("apply:\n%s", out)
			}
			if got := strings.TrimSpace(h.exec("", "stat", "-c", "%U", "/home/alice/new/.git/config")); got != "alice" {
				t.Fatalf("new checkout belongs to %s", got)
			}
			if _, out, code := routeApply(t, h, step("/opt/co")); code != 0 && !strings.Contains(out, "dubious") {
				t.Fatalf("apply:\n%s", out)
			}
		})
	}
}
