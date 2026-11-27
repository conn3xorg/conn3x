// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"embed"
	"flag"
	"io/fs"
	"os"
	"testing"
)

// The sources scripts.tar.gz is packed from. Only the test binary embeds them.
//
//go:embed *.ps1 lib/*.ps1
var sources embed.FS

var update = flag.Bool("update", false, "rewrite scripts.tar.gz from the .ps1 sources")

// pack is the only way scripts.tar.gz is made: fixed headers and no times, so
// the same sources always give the same bytes.
func pack(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(zw)
	err = fs.WalkDir(sources, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := sources.ReadFile(name)
		if err != nil {
			return err
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(b)), Format: tar.FormatUSTAR}); err != nil {
			return err
		}
		_, err = tw.Write(b)
		return err
	})
	if err == nil {
		err = tw.Close()
	}
	if err == nil {
		err = zw.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestScriptsPack checks that the embedded archive is exactly what the sources
// pack to, so nothing but the reviewed .ps1 files can ride along in it, and
// that every source comes back out of it byte for byte.
func TestScriptsPack(t *testing.T) {
	want := pack(t)
	if *update {
		if err := os.WriteFile("scripts.tar.gz", want, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if !bytes.Equal(packed, want) {
		t.Fatal("scripts.tar.gz does not match the .ps1 sources: run go test -run TestScriptsPack -update in this directory")
	}
	n := 0
	err := fs.WalkDir(sources, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		n++
		b, err := sources.ReadFile(name)
		if err != nil {
			return err
		}
		if got, ok := scripts()[name]; !ok || got != string(b) {
			t.Errorf("%s does not round-trip through scripts.tar.gz", name)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(scripts()) != n {
		t.Errorf("scripts.tar.gz holds %d files, the sources %d", len(scripts()), n)
	}
}
