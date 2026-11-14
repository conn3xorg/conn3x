// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// xml_value changes one attribute and adds one element in an XML file, and
// leaves every other byte, comments and the declaration included.
func TestXMLValue(t *testing.T) {
	h := startHost(t, "debian13")
	orig := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!-- Tomcat's, cut down -->\n<Server port=\"8005\">\n\t<Service name=\"Catalina\">\n\t\t<Connector port=\"8080\" protocol=\"HTTP/1.1\"/>\n\t\t<Engine name=\"Catalina\">\n\t\t\t<Realm className=\"x\"/>\n\t\t</Engine>\n\t</Service>\n</Server>\n"
	h.exec(orig, "sh", "-c", "cat > /etc/server.xml")
	w := newWorkdir(t, "xmlvalue")
	w.writeAs("main.circuit.hcl", circuitVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts})
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	want := strings.Replace(strings.Replace(orig, `protocol="HTTP/1.1"`, `protocol="HTTP/2"`, 1),
		"<Realm className=\"x\"/>\n", "<Realm className=\"x\"/>\n\t\t\t<Valve className=\"AccessLogValve\" pattern=\"common\"/>\n", 1)
	if got := h.exec("", "cat", "/etc/server.xml"); got != want {
		t.Fatalf("after apply:\n%s\nwant:\n%s", got, want)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}
	h.exec("", "sed", "-i", "s|HTTP/2|HTTP/1.1|", "/etc/server.xml")
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "1 to change") {
		t.Fatalf("plan after a change by hand:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := h.exec("", "cat", "/etc/server.xml"); got != want {
		t.Fatalf("after putting it back:\n%s", got)
	}
	// on_remove = "delete" takes the attribute out; the Valve it was on stays.
	w.mustConn3x("destroy", "-auto-approve", "-no-color")
	if got := h.exec("", "cat", "/etc/server.xml"); strings.Contains(got, "pattern=") || !strings.Contains(got, "HTTP/2") {
		t.Fatalf("after destroy:\n%s", got)
	}
}
