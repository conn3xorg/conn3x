// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package edit

import "testing"

func TestApplyXMLValue(t *testing.T) {
	doc := `<?xml version="1.0" encoding="UTF-8"?>
<!-- Tomcat -->
<Server port="8005" shutdown="SHUTDOWN">
  <Service name="Catalina">
    <Connector port="8080" protocol="HTTP/1.1" title="see port='9'"/>
    <Connector port="8443" protocol="HTTP/1.1"/>
    <Engine name="Catalina" defaultHost="localhost">
      <Realm className="x"/>
    </Engine>
  </Service>
  <Note>hello</Note>
</Server>
`
	conn := `/Server/Service/Connector[@port='8080']`
	for _, c := range []struct {
		name string
		c    XMLValue
		from string
		to   string
	}{
		{"change an attribute", XMLValue{XPath: conn + "/@protocol", Value: "HTTP/2"}, `<Connector port="8080" protocol="HTTP/1.1" title`, `<Connector port="8080" protocol="HTTP/2" title`},
		{"add an attribute", XMLValue{XPath: conn + "/@maxThreads", Value: "200"}, `title="see port='9'"/>`, `title="see port='9'" maxThreads="200"/>`},
		{"drop an attribute", XMLValue{XPath: "/Server/@shutdown", State: Absent}, `<Server port="8005" shutdown="SHUTDOWN">`, `<Server port="8005">`},
		{"element text", XMLValue{XPath: "/Server/Note", Value: "a < b"}, `<Note>hello</Note>`, `<Note>a &lt; b</Note>`},
		{"text into an empty element", XMLValue{XPath: "/Server/Service/Engine/Realm", Value: "r"}, `<Realm className="x"/>`, `<Realm className="x">r</Realm>`},
		{"by index", XMLValue{XPath: "/Server/Service/Connector[2]/@port", Value: "9443"}, `<Connector port="8443"`, `<Connector port="9443"`},
		{"add an element, indented", XMLValue{XPath: "/Server/Service/Engine/Valve[@className='y']/@pattern", Value: "common"}, "<Realm className=\"x\"/>\n    </Engine>", "<Realm className=\"x\"/>\n      <Valve className=\"y\" pattern=\"common\"/>\n    </Engine>"},
		{"drop an element and its line", XMLValue{XPath: "/Server/Service/Connector[@port='8443']", State: Absent}, "\n    <Connector port=\"8443\" protocol=\"HTTP/1.1\"/>", ""},
	} {
		got, err := ApplyXMLValue(doc, c.c)
		want := replaceOnce(doc, c.from, c.to)
		if err != nil || got != want {
			t.Errorf("%s:\n got %q, %v\nwant %q", c.name, got, err, want)
			continue
		}
		if again, _ := ApplyXMLValue(got, c.c); again != got {
			t.Errorf("%s: not idempotent:\n%s", c.name, again)
		}
	}
	// An attribute name inside another attribute's value isn't the attribute.
	if got, err := ApplyXMLValue(`<a title="see port='9'" port="1"/>`, XMLValue{XPath: "/a/@port", Value: "2"}); err != nil || got != `<a title="see port='9'" port="2"/>` {
		t.Errorf("port inside title: %q, %v", got, err)
	}
	if got, _ := ApplyXMLValue(doc, XMLValue{XPath: conn + "/@protocol", Value: "HTTP/1.1"}); got != doc {
		t.Error("an equal value was rewritten")
	}
	if got, _ := ApplyXMLValue(doc, XMLValue{XPath: "/Server/Nope/Thing", State: Absent}); got != doc {
		t.Error("absent and missing changed the file")
	}
	for name, c := range map[string]XMLValue{
		"relative":      {XPath: "Server/Note", Value: "x"},
		"descendant":    {XPath: "//Note", Value: "x"},
		"two match":     {XPath: "/Server/Service/Connector/@port", Value: "1"},
		"has children":  {XPath: "/Server/Service", Value: "x"},
		"wrong root":    {XPath: "/Config/a", Value: "x"},
		"deep missing":  {XPath: "/Server/A/B", Value: "x"},
		"root absent":   {XPath: "/Server", State: Absent},
		"bad predicate": {XPath: "/Server/Service[name='x']", Value: "x"},
		"bad state":     {XPath: "/Server/Note", Value: "x", State: "gone"},
	} {
		if _, err := ApplyXMLValue(doc, c); err == nil {
			t.Errorf("%s passed", name)
		}
	}
	if _, err := ApplyXMLValue("<a><b></a>", XMLValue{XPath: "/a/b", Value: "x"}); err == nil {
		t.Error("malformed XML passed")
	}
}

func replaceOnce(s, from, to string) string {
	for i := 0; i+len(from) <= len(s); i++ {
		if s[i:i+len(from)] == from {
			return s[:i] + to + s[i+len(from):]
		}
	}
	return "MISSING " + from
}
