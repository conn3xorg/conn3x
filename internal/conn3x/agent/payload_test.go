// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package agent

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"os"
	"testing"
	"testing/fstest"
)

func gzipped(t testing.TB, raw []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w, _ := gzip.NewWriterLevel(&b, gzip.BestCompression)
	_, _ = w.Write(raw)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestEmbeddedMissingPayload(t *testing.T) {
	old := payloadFS
	t.Cleanup(func() { payloadFS = old })

	// A build without scripts/build-agent.sh has only the README.
	payloadFS = fstest.MapFS{"payload/README.md": {Data: []byte("x")}}
	for _, arch := range []string{"amd64", "arm64", "mips"} {
		if _, _, err := Embedded(arch); !errors.Is(err, ErrUnavailable) {
			t.Errorf("Embedded(%s) = %v, want ErrUnavailable", arch, err)
		}
	}

	raw := []byte("not really an ELF binary")
	gz := gzipped(t, raw)
	payloadFS = fstest.MapFS{"payload/conn3x-agent-linux-arm64.gz": {Data: gz}}
	got, sum, err := Embedded("arm64")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, gz) || sum != sha256.Sum256(raw) {
		t.Fatalf("Embedded(arm64) = %d bytes, sum %x; want the gzip and the sum of what it holds", len(got), sum)
	}
	if _, _, err := Embedded("amd64"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Embedded(amd64) = %v, want ErrUnavailable", err)
	}

	// A payload that isn't gzip is a broken build, not a missing one.
	payloadFS = fstest.MapFS{"payload/conn3x-agent-linux-amd64.gz": {Data: raw}}
	if _, _, err := Embedded("amd64"); err == nil || errors.Is(err, ErrUnavailable) {
		t.Errorf("Embedded of a non-gzip payload = %v, want another error", err)
	}
}

// TestEmbeddedPresent checks a release build: CI sets CONN3X_REQUIRE_AGENT=1
// after building, so a build that lost its agents fails.
func TestEmbeddedPresent(t *testing.T) {
	if os.Getenv("CONN3X_REQUIRE_AGENT") != "1" {
		t.Skip("set CONN3X_REQUIRE_AGENT=1 to check that this build embeds the agents")
	}
	for _, arch := range []string{"amd64", "arm64"} {
		gz, _, err := Embedded(arch)
		if err != nil {
			t.Errorf("linux/%s: %v", arch, err)
			continue
		}
		raw, err := gunzip(gz)
		if err != nil || !bytes.HasPrefix(raw, []byte("\x7fELF")) {
			t.Errorf("linux/%s: the embedded agent is not an ELF binary (%v)", arch, err)
		}
	}
}
