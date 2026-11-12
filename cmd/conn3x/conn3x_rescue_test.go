// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/configs"
)

func TestRescueHosts(t *testing.T) {
	stream := filepath.Join(t.TempDir(), "apply.jsonl")
	lines := []string{
		`{"type":"apply_errored","hook":{"resource":{"addr":"conn3x_file.app__config[\"web10\"]"}}}`,
		`{"type":"apply_errored","hook":{"resource":{"addr":"conn3x_file.app__config[\"web2\"]"}}}`,
		`{"type":"apply_errored","hook":{"resource":{"addr":"conn3x_service_action.app__restart[\"web3\"]"}}}`,
		`{"type":"apply_complete","hook":{"resource":{"addr":"conn3x_file.app__config[\"web1\"]"}}}`,
		`{"type":"apply_errored","hook":{"resource":{"addr":"conn3x_file.db__config[\"db1\"]"}}}`,
		`{"type":"apply_errored","hook":{"resource":{"addr":"module.m.conn3x_file.app__config[\"web4\"]"}}}`,
	}
	if err := os.WriteFile(stream, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &batchRun{rescues: []configs.Conn3xRescue{
		{Circuit: "app", Name: "restore", Watches: []string{"config", "restart"}},
		{Circuit: "app", Name: "page", Watches: []string{"restart"}},
	}}
	by, all, err := r.rescueHosts(stream)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(all, []string{"web2", "web3", "web10"}) || !slices.Equal(by["app__restore"], all) || !slices.Equal(by["app__page"], []string{"web3"}) || len(by) != 2 {
		t.Errorf("got %v, %v", by, all)
	}
	if got := orList([]string{"a", "b", "c"}); got != "a, b or c" {
		t.Errorf("orList = %q", got)
	}
}
