// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/command/e2etest/fakeocireg"
)

// A shared circuit installs from an OCI registry, as any module does, and
// its steps validate. The registry is OpenTofu's fake one, serving an OCI
// layout built here from a small circuit. Its certificate reaches conn3x
// through SSL_CERT_FILE, which Go reads only on Linux, so this runs there.
func TestCircuitFromOCIRegistry(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SSL_CERT_FILE, which points conn3x at the fake registry's certificate, works only on Linux")
	}
	layout := t.TempDir()
	put := func(b []byte) (string, int) {
		sum := sha256.Sum256(b)
		d := hex.EncodeToString(sum[:])
		p := filepath.Join(layout, "blobs", "sha256", d)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return "sha256:" + d, len(b)
	}

	// The circuit, as the module package's one .zip layer.
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	for name, body := range map[string]string{
		"main.circuit.hcl": `circuit "motd" {
  hosts = var.hosts
  ssh {
    user = "root"
  }
  step "motd" {
    file {
      path    = "/etc/motd"
      content = var.message
    }
  }
}
`,
		"variables.tf": `variable "hosts" {
  type = map(string)
}
variable "message" {
  type = string
}
`,
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	pkgDigest, pkgSize := put(zbuf.Bytes())
	emptyDigest, emptySize := put([]byte("{}"))
	manifest, _ := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"artifactType":  "application/vnd.opentofu.modulepkg",
		"config":        map[string]any{"mediaType": "application/vnd.oci.empty.v1+json", "digest": emptyDigest, "size": emptySize},
		"layers":        []any{map[string]any{"mediaType": "archive/zip", "digest": pkgDigest, "size": pkgSize}},
	})
	manDigest, manSize := put(manifest)
	index, _ := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.index.v1+json",
		"manifests": []any{map[string]any{
			"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": manDigest, "size": manSize,
			"artifactType": "application/vnd.opentofu.modulepkg",
			"annotations":  map[string]string{"org.opencontainers.image.ref.name": "latest"},
		}},
	})
	for name, body := range map[string][]byte{"index.json": index, "oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`)} {
		if err := os.WriteFile(filepath.Join(layout, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	srv, err := fakeocireg.NewServer(t.Context(), map[string]string{"circuits/motd": layout})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cert := filepath.Join(t.TempDir(), "registry.crt")
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", cert)

	w := &workdir{t: t, dir: t.TempDir()}
	root := `module "motd" {
  source  = "oci://` + srv.Listener.Addr().String() + `/circuits/motd"
  hosts   = { web1 = "203.0.113.10" }
  message = "hello\n"
}
`
	if err := os.WriteFile(filepath.Join(w.dir, "main.tf"), []byte(root), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, code := w.conn3x("init", "-backend=false", "-no-color"); code != 0 {
		t.Fatalf("init from the OCI registry (exit %d):\n%s", code, out)
	}
	if out, code := w.conn3x("validate", "-no-color"); code != 0 || !strings.Contains(out, "valid") {
		t.Fatalf("validate (exit %d):\n%s", code, out)
	}
}
