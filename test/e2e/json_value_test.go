// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type jsonValueVars struct {
	Port, KeyFile, KnownHosts string
	Port2                     int
}

// json_value changes one value in a JSON file and nothing else: the
// comment-free formatting, key order and the values it doesn't own stay
// byte for byte.
func TestJSONValue(t *testing.T) {
	h := startHost(t, "debian13")
	orig := "{\n    \"name\": \"app\",\n    \"server\": {\n        \"port\": 8080,\n        \"tls\": false\n    },\n    \"zones\": [\"a\", \"b\"]\n}\n"
	h.exec(orig, "sh", "-c", "cat > /etc/app.json")
	w := newWorkdir(t, "jsonvalue")
	vars := jsonValueVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, Port2: 9090}
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	want := "{\n    \"name\": \"app\",\n    \"server\": {\n        \"port\": 9090,\n        \"tls\": false\n    },\n    \"zones\": [\"a\", \"b\"],\n    \"log\": {\"level\":\"info\"}\n}\n"
	if got := h.exec("", "cat", "/etc/app.json"); got != want {
		t.Fatalf("after apply:\n%s\nwant:\n%s", got, want)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}

	// Someone sets the port by hand: the plan sees it, and apply puts it back.
	h.exec("", "sed", "-i", "s/9090/7000/", "/etc/app.json")
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "1 to change") {
		t.Fatalf("plan after a change by hand:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := h.exec("", "cat", "/etc/app.json"); got != want {
		t.Fatalf("after putting it back:\n%s", got)
	}

	// on_remove = "delete" takes its key out, leaving the object it was in;
	// the port stays.
	w.mustConn3x("destroy", "-auto-approve", "-no-color")
	if got := h.exec("", "cat", "/etc/app.json"); strings.Contains(got, "level") || !strings.Contains(got, "9090") {
		t.Fatalf("after destroy:\n%s", got)
	}
}
