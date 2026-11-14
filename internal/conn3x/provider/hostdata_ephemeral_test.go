// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

// conn3x_hostdata decrypts a SOPS layer with the age key sops would use,
// and a plain layer above it still wins.
func TestOpenHostdata(t *testing.T) {
	keys, _ := filepath.Abs(filepath.Join("..", "secrets", "testdata", "test-key.txt"))
	t.Setenv("SOPS_AGE_KEY_FILE", keys)
	t.Setenv("SOPS_AGE_KEY", "")
	dir := t.TempDir()
	sops, err := os.ReadFile(filepath.Join("..", "secrets", "testdata", "secrets.sops.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{
		"hierarchy.yaml":   []byte("hierarchy: [\"hosts/{host}.yaml\", common.sops.yaml]\n"),
		"hosts/web1.yaml":  []byte("port: \"6432\"\n"),
		"common.sops.yaml": sops,
	} {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	vars := cty.ObjectVal(map[string]cty.Value{"host": cty.StringVal("web1")})
	resp := openHostdata(providers.OpenEphemeralResourceRequest{TypeName: hostdataType, Config: cty.ObjectVal(map[string]cty.Value{
		"dir": cty.StringVal(dir), "vars": vars, "values": cty.NullVal(cty.DynamicPseudoType), "from": cty.NullVal(cty.Map(cty.String)),
	})})
	if err := resp.Diagnostics.Err(); err != nil {
		t.Fatal(err)
	}
	values, from := resp.Result.GetAttr("values"), resp.Result.GetAttr("from").AsValueMap()
	if got := values.GetAttr("db_password").AsString(); got != "hunter2" || from["db_password"].AsString() != "common.sops.yaml" {
		t.Errorf("db_password = %q from %s", got, from["db_password"].AsString())
	}
	if got := values.GetAttr("port").AsString(); got != "6432" || from["port"].AsString() != "hosts/web1.yaml" {
		t.Errorf("port = %q from %s: the host layer should win", got, from["port"].AsString())
	}
	if values.Type().HasAttribute("sops") {
		t.Error("the sops block came through as a value")
	}

	// The function still refuses it, and says where to go instead.
	if res := hostData([]cty.Value{cty.StringVal(dir), vars}); res.Error == nil {
		t.Error("hostdata read an encrypted layer")
	}
}
