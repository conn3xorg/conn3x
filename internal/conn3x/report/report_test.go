// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWhere(t *testing.T) {
	for addr, want := range map[string][3]string{
		`conn3x_file.web__motd["web1"]`:                {"web1", "web.motd", ""},
		`conn3x_package.web__tools["web2/jq"]`:         {"web2", "web.tools", "jq"},
		`module.site.conn3x_file.site__conf["box"]`:    {"box", "module.site.site.conf", ""},
		`module.x["a"].conn3x_service.app__run["db1"]`: {"db1", `module.x["a"].app.run`, ""},
	} {
		host, step, item, ok := Where(addr)
		if !ok || [3]string{host, step, item} != want {
			t.Errorf("Where(%s) = %q %q %q %v, want %q", addr, host, step, item, ok, want)
		}
	}
	for _, addr := range []string{`digitalocean_droplet.web`, `conn3x_file.nounderscores["h"]`, `aws_instance.x["a"]`} {
		if _, _, _, ok := Where(addr); ok {
			t.Errorf("Where(%s) took it for a step", addr)
		}
	}
}

// A per_host apply where web2's first step failed: web1's steps are ok,
// web2's next step was skipped because of it, a cloud resource is listed
// apart, and the error is as the terminal printed it, on the step and in
// errors.
func TestFromApply(t *testing.T) {
	stream := strings.Join([]string{
		`{"type":"version","ui":"1.2"}`,
		`{"type":"planned_change","change":{"resource":{"addr":"digitalocean_droplet.web","resource_type":"digitalocean_droplet"},"action":"update"}}`,
		`{"type":"planned_change","change":{"resource":{"addr":"conn3x_file.web__conf[\"web1\"]","resource_type":"conn3x_file"},"action":"create"}}`,
		`{"type":"planned_change","change":{"resource":{"addr":"conn3x_file.web__conf[\"web2\"]","resource_type":"conn3x_file"},"action":"create"}}`,
		`{"type":"planned_change","change":{"resource":{"addr":"conn3x_service.web__run[\"web1\"]","resource_type":"conn3x_service"},"action":"create"}}`,
		`{"type":"planned_change","change":{"resource":{"addr":"conn3x_service.web__run[\"web2\"]","resource_type":"conn3x_service"},"action":"create"}}`,
		`{"type":"planned_change","change":{"resource":{"addr":"conn3x_file.web__same[\"web1\"]","resource_type":"conn3x_file"},"action":"noop"}}`,
		`{"type":"apply_start","hook":{"resource":{"addr":"digitalocean_droplet.web"},"action":"update"}}`,
		`{"type":"apply_complete","hook":{"resource":{"addr":"digitalocean_droplet.web"},"action":"update","elapsed_seconds":3}}`,
		`{"type":"apply_start","hook":{"resource":{"addr":"conn3x_file.web__conf[\"web1\"]"},"action":"create"}}`,
		`{"type":"apply_complete","hook":{"resource":{"addr":"conn3x_file.web__conf[\"web1\"]"},"action":"create","elapsed_seconds":1}}`,
		`{"type":"apply_start","hook":{"resource":{"addr":"conn3x_file.web__conf[\"web2\"]"},"action":"create"}}`,
		`{"type":"apply_errored","hook":{"resource":{"addr":"conn3x_file.web__conf[\"web2\"]"},"action":"create","elapsed_seconds":2}}`,
		`{"type":"apply_start","hook":{"resource":{"addr":"conn3x_service.web__run[\"web1\"]"},"action":"create"}}`,
		`{"type":"apply_complete","hook":{"resource":{"addr":"conn3x_service.web__run[\"web1\"]"},"action":"create","elapsed_seconds":4}}`,
		`{"type":"diagnostic","diagnostic":{"severity":"error","summary":"writing /etc/web.conf: permission denied","detail":"","address":"conn3x_file.web__conf[\"web2\"]"}}`,
		`{"type":"diagnostic","diagnostic":{"severity":"warning","summary":"a warning","detail":""}}`,
	}, "\n")
	r := New("apply", time.Date(2026, 11, 8, 9, 0, 0, 0, time.UTC))
	if err := r.FromApply(strings.NewReader(stream), false); err != nil {
		t.Fatal(err)
	}
	web1, web2 := r.Hosts["web1"].Steps, r.Hosts["web2"].Steps
	if len(web1) != 2 || web1[0].Status != StatusOK || !web1[0].Changed || web1[1].Step != "web.run" || *web1[1].Seconds != 4 {
		t.Errorf("web1 = %+v", web1)
	}
	if len(web2) != 2 || web2[0].Status != StatusFailed || !strings.HasPrefix(web2[0].Error, "Error: writing /etc/web.conf: permission denied") || !strings.Contains(web2[0].Error, "with conn3x_file.web__conf") {
		t.Errorf("web2[0] = %+v", web2[0])
	}
	if web2[1].Status != StatusSkipped || web2[1].Reason != ReasonEarlierFailed || web2[1].Changed {
		t.Errorf("web2[1] = %+v", web2[1])
	}
	if len(r.Cloud) != 1 || r.Cloud[0].Address != "digitalocean_droplet.web" || r.Cloud[0].Status != StatusOK {
		t.Errorf("cloud = %+v", r.Cloud)
	}
	if len(r.Errors) != 1 || r.Success {
		t.Errorf("errors = %q, success %v", r.Errors, r.Success)
	}

	var buf bytes.Buffer
	if err := r.Write(&buf, time.Date(2026, 11, 8, 9, 1, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if err := Validate(buf.Bytes()); err != nil {
		t.Fatalf("the report doesn't match the schema: %v\n%s", err, buf.String())
	}
}

func TestDriftReport(t *testing.T) {
	r := New("drift", time.Now())
	r.Success = true
	r.AddDrift(`conn3x_file.web__motd["web1"]`, false)
	r.AddDrift(`digitalocean_droplet.web`, true)
	var buf bytes.Buffer
	if err := r.Write(&buf, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := Validate(buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	if r.Drift[0].Address != "conn3x_file.web__motd[\"web1\"]" || r.Drift[0].Host != "web1" || r.Drift[1].Kind != "gone" || r.Drift[1].Host != "" {
		t.Errorf("drift = %+v", r.Drift)
	}
}

// Validate refuses what the schema doesn't allow, and a schema keyword it
// doesn't understand.
func TestValidate(t *testing.T) {
	ok, _ := json.Marshal(New("apply", time.Now()))
	if err := Validate(ok); err != nil {
		t.Fatalf("an empty report: %v", err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"unknown field":  func(m map[string]any) { m["extra"] = 1 },
		"bad command":    func(m map[string]any) { m["command"] = "plan" },
		"missing errors": func(m map[string]any) { delete(m, "errors") },
		"bad status": func(m map[string]any) {
			m["hosts"] = map[string]any{"h": map[string]any{"steps": []any{map[string]any{"step": "a.b", "address": "x", "module": "file", "action": "create", "changed": true, "status": "done"}}}}
		},
	} {
		var m map[string]any
		_ = json.Unmarshal(ok, &m)
		mutate(m)
		b, _ := json.Marshal(m)
		if err := Validate(b); err == nil {
			t.Errorf("%s: passed", name)
		}
	}
	saved := Schema
	defer func() { Schema = saved }()
	Schema = []byte(`{"type":"object","minProperties":1}`)
	if err := Validate([]byte(`{}`)); err == nil || !strings.Contains(err.Error(), "minProperties") {
		t.Errorf("an unknown keyword: %v", err)
	}
}

// The schema file is the one docs link to; keep it valid JSON with an $id.
func TestSchemaFile(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(".", "report.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	if err := json.Unmarshal(src, &s); err != nil || s["$id"] == nil {
		t.Fatalf("schema: %v", err)
	}
}
