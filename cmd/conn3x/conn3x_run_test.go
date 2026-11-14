// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunArgsFileSrc(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "app.conf")
	if err := os.WriteFile(src, []byte("port = 80\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.WriteFile(bin, []byte{0xff, 0xfe, 0}, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	args, err := runArgs(ctx, "file", "conn3x_file", "src="+src+" path=/etc/app.conf mode=0644", false)
	if err != nil || args["content"].AsString() != "port = 80\n" || args["path"].AsString() != "/etc/app.conf" {
		t.Fatalf("args = %v, %v", args, err)
	}
	for raw, want := range map[string]string{
		"src=" + src + " content=x path=/a": "is given twice, or with src",
		"content=x src=" + src + " path=/a": "src or content, not both",
		"src=" + bin + " path=/a":           "isn't text",
		"src=/nope/x path=/a":               "src:",
	} {
		if _, err := runArgs(ctx, "file", "conn3x_file", raw, false); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", raw, err, want)
		}
	}
	// Only file takes src.
	if _, err := runArgs(ctx, "line", "conn3x_line", "src="+src+" path=/a", false); err == nil {
		t.Error("line took src")
	}
}
