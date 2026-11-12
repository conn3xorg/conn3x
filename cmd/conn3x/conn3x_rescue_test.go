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
		{Circuit: "app", Name: "restore", Kind: "rescue", Watches: []string{"config", "restart"}},
		{Circuit: "app", Name: "page", Kind: "rescue", Watches: []string{"restart"}},
	}}
	ph, err := r.rescueHosts(stream, "rescue")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ph.all, []string{"web2", "web3", "web10"}) || !slices.Equal(ph.byBlock["app__restore"], ph.all) || !slices.Equal(ph.byBlock["app__page"], []string{"web3"}) || len(ph.byBlock) != 2 {
		t.Errorf("got %+v", ph)
	}
	r.rescues = append(r.rescues, configs.Conn3xRescue{Circuit: "app", Name: "lb", Kind: "always", Watches: []string{"config"}})
	if ph, err := r.rescueHosts(stream, "always"); err != nil || !slices.Equal(ph.all, []string{"web1", "web2", "web10"}) || len(ph.byBlock) != 1 {
		t.Errorf("always: %+v, %v", ph, err)
	}
	r.rescues = append(r.rescues, configs.Conn3xRescue{Circuit: "app", Name: "drain", Kind: "prereq", Watches: []string{"config"}})
	p, _ := readBatchPlan([]byte(`{"resource_changes": [
		{"address": "a", "mode": "managed", "type": "conn3x_file", "name": "app__config", "index": "web2", "change": {"actions": ["update"]}},
		{"address": "b", "mode": "managed", "type": "conn3x_file", "name": "app__config", "index": "web1", "change": {"actions": ["no-op"]}},
		{"address": "c", "mode": "managed", "type": "conn3x_file", "name": "app__other", "index": "web3", "change": {"actions": ["create"]}}
	]}`))
	if ph := r.prereqHosts(p); !slices.Equal(ph.all, []string{"web2"}) || len(ph.byBlock) != 1 {
		t.Errorf("prereq: %+v", ph)
	}
	if got := orList([]string{"a", "b", "c"}); got != "a, b or c" {
		t.Errorf("orList = %q", got)
	}
}
