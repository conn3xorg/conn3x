// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package hostdata

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

func write(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLoadLayers(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{
		HierarchyFile:      "hierarchy:\n  - hosts/{host}.yaml\n  - groups/{group}.yaml\n  - env/{env}.yaml\n  - common.yaml\n",
		"common.yaml":      "ntp_servers: [0.pool.ntp.org]\nlog_level: info\nmotd: welcome\n",
		"env/prod.yaml":    "log_level: warn\n",
		"groups/web.yaml":  "nginx_workers: 4\nmotd: web server\n",
		"groups/eu.yaml":   "ntp_servers: [ntp.eu.example]\nmotd: eu server\n",
		"hosts/web1.yaml":  "nginx_workers: 8\n",
		"hosts/other.yaml": "log_level: debug\n",
	})
	res, err := Load(dir, map[string][]string{"host": {"web1"}, "group": {"web", "eu"}, "env": {"prod"}})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"nginx_workers": "hosts/web1.yaml",
		"motd":          "groups/web.yaml", // web comes before eu
		"ntp_servers":   "groups/eu.yaml",
		"log_level":     "env/prod.yaml",
	}
	for k, from := range want {
		if res.From[k] != from {
			t.Errorf("%s came from %q, want %q", k, res.From[k], from)
		}
	}
	if v := res.Values["nginx_workers"]; !v.RawEquals(cty.NumberIntVal(8)) {
		t.Errorf("nginx_workers = %#v", v)
	}
	if v := res.Values["ntp_servers"]; v.LengthInt() != 1 || v.Index(cty.NumberIntVal(0)).AsString() != "ntp.eu.example" {
		t.Errorf("ntp_servers = %#v", v)
	}
}

func TestLoadRefuses(t *testing.T) {
	for name, tc := range map[string]struct {
		files map[string]string
		vars  map[string][]string
		want  string
	}{
		"no hierarchy":  {map[string]string{"common.yaml": "a: 1\n"}, nil, "hierarchy.yaml"},
		"unknown var":   {map[string]string{HierarchyFile: "hierarchy: [\"hosts/{hostname}.yaml\"]\n"}, map[string][]string{"host": {"web1"}}, "{hostname}"},
		"path escape":   {map[string]string{HierarchyFile: "hierarchy: [\"hosts/{host}.yaml\"]\n"}, map[string][]string{"host": {"../../etc/passwd"}}, "letters, digits"},
		"leaves dir":    {map[string]string{HierarchyFile: "hierarchy: [../outside.yaml]\n"}, nil, "leaves the data directory"},
		"sops":          {map[string]string{HierarchyFile: "hierarchy: [common.yaml]\n", "common.yaml": "password: ENC[x]\nsops:\n  version: 3.9.0\n"}, nil, "conn3x_secrets"},
		"not a mapping": {map[string]string{HierarchyFile: "hierarchy: [common.yaml]\n", "common.yaml": "- a\n- b\n"}, nil, "mapping"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			write(t, dir, tc.files)
			_, err := Load(dir, tc.vars)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}
