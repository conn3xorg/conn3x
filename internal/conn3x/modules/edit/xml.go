// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package edit

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// XMLValue is one element's text or one attribute in an XML file, named by
// a small XPath: /Server/Service/Connector[@port='8080']/@protocol.
type XMLValue struct {
	XPath string
	Value string
	State State
}

type xmlStep struct {
	name  string
	attrs [][2]string // [@name='value'] predicates
	index int         // [n], 1-based; 0 for any
}

var (
	xmlStepRe = regexp.MustCompile(`^([A-Za-z_][\w.-]*)((?:\[[^\]]+\])*)$`)
	xmlPredRe = regexp.MustCompile(`\[([^\]]+)\]`)
	xmlAttrRe = regexp.MustCompile(`^@([A-Za-z_][\w.:-]*)\s*=\s*(?:'([^']*)'|"([^"]*)")$`)
	xmlNameRe = regexp.MustCompile(`^[A-Za-z_][\w.:-]*$`)
)

// parse splits the XPath into element steps and, after a final /@, an
// attribute name.
func (c XMLValue) parse() ([]xmlStep, string, error) {
	p := c.XPath
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
		return nil, "", fmt.Errorf("xpath %q must start at the root with one /, such as /Server/Service", c.XPath)
	}
	parts := strings.Split(p[1:], "/")
	attr := ""
	if last := parts[len(parts)-1]; strings.HasPrefix(last, "@") {
		attr, parts = last[1:], parts[:len(parts)-1]
		if !xmlNameRe.MatchString(attr) {
			return nil, "", fmt.Errorf("xpath %q: %q isn't an attribute name", c.XPath, attr)
		}
	}
	if len(parts) == 0 {
		return nil, "", fmt.Errorf("xpath %q names no element", c.XPath)
	}
	var steps []xmlStep
	for _, part := range parts {
		m := xmlStepRe.FindStringSubmatch(part)
		if m == nil {
			return nil, "", fmt.Errorf("xpath %q: %q isn't an element name with [@attr='value'] or [n] predicates; Conn3x reads that much XPath", c.XPath, part)
		}
		st := xmlStep{name: m[1]}
		for _, pm := range xmlPredRe.FindAllStringSubmatch(m[2], -1) {
			pred := strings.TrimSpace(pm[1])
			if n, err := strconv.Atoi(pred); err == nil && n >= 1 {
				st.index = n
				continue
			}
			am := xmlAttrRe.FindStringSubmatch(pred)
			if am == nil {
				return nil, "", fmt.Errorf("xpath %q: [%s] isn't [@attr='value'] or [n]", c.XPath, pred)
			}
			st.attrs = append(st.attrs, [2]string{am[1], am[2] + am[3]})
		}
		steps = append(steps, st)
	}
	return steps, attr, nil
}

// Validate checks an XMLValue before anything reaches the host.
func (c XMLValue) Validate() error {
	steps, attr, err := c.parse()
	if err != nil {
		return err
	}
	// Setting what the last step picks its element by would make the path
	// miss it next time, and add another.
	for _, p := range steps[len(steps)-1].attrs {
		if attr != "" && p[0] == attr && c.State != Absent {
			return fmt.Errorf("xpath %q picks the element by @%s and sets it; pick it by something else, such as [n]", c.XPath, attr)
		}
	}
	switch c.State {
	case Present, "", Absent:
	default:
		return fmt.Errorf("state must be %q or %q, not %q", Present, Absent, c.State)
	}
	return nil
}

// xmlElem is an element and where its parts sit in the document.
type xmlElem struct {
	name             string
	attrs            []xml.Attr
	start, startEnd  int // the start tag: [start, startEnd)
	end, endEnd      int // the end tag; equal to startEnd for <a/>
	selfClosing      bool
	children         []*xmlElem
	hasChildElements bool
}

func scanXML(b []byte) (*xmlElem, error) {
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = true
	var root *xmlElem
	var stack []*xmlElem
	for {
		before := int(d.InputOffset())
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("the file isn't well-formed XML: %w", err)
		}
		after := int(d.InputOffset())
		switch t := tok.(type) {
		case xml.StartElement:
			// The token starts at its '<', after any text before it.
			s := before + bytes.IndexByte(b[before:after], '<')
			e := &xmlElem{name: t.Name.Local, attrs: t.Attr, start: s, startEnd: after, selfClosing: bytes.HasSuffix(bytes.TrimRight(b[s:after-1], " \t\r\n"), []byte("/"))}
			if len(stack) > 0 {
				p := stack[len(stack)-1]
				p.children = append(p.children, e)
				p.hasChildElements = true
			} else if root == nil {
				root = e
			}
			stack = append(stack, e)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, errors.New("the file isn't well-formed XML: an end tag with no start")
			}
			e := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if e.selfClosing {
				e.end, e.endEnd = e.startEnd, e.startEnd
			} else {
				e.end, e.endEnd = before+bytes.IndexByte(b[before:after], '<'), after
			}
		}
	}
	if root == nil {
		return nil, errors.New("the file has no root element")
	}
	return root, nil
}

func (st xmlStep) matches(e *xmlElem) bool {
	if e.name != st.name {
		return false
	}
	for _, want := range st.attrs {
		found := false
		for _, a := range e.attrs {
			if a.Name.Local == want[0] && a.Value == want[1] {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func escapeXML(s string, attr bool) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	out := buf.String()
	if attr {
		out = strings.ReplaceAll(out, `"`, "&#34;")
	} else {
		// EscapeText escapes newlines and tabs, which text keeps as they are.
		out = strings.NewReplacer("&#xA;", "\n", "&#x9;", "\t").Replace(out)
	}
	return out
}

// ApplyXMLValue returns content with the element's text or the attribute
// set, or taken out, and every other byte as it was.
func ApplyXMLValue(content string, c XMLValue) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	steps, attr, _ := c.parse()
	b := []byte(content)
	root, err := scanXML(b)
	if err != nil {
		return "", err
	}
	if !steps[0].matches(root) || steps[0].index > 1 {
		if c.State == Absent {
			return content, nil
		}
		return "", fmt.Errorf("xpath %q: the root element is <%s>", c.XPath, root.name)
	}
	cur := root
	for n, st := range steps[1:] {
		var hits []*xmlElem
		for _, ch := range cur.children {
			if st.matches(ch) {
				hits = append(hits, ch)
			}
		}
		switch {
		case st.index > 0 && st.index <= len(hits):
			hits = hits[st.index-1 : st.index]
		case st.index > 0:
			hits = nil
		case len(hits) > 1:
			return "", fmt.Errorf("xpath %q: %d elements match %s; add [@attr='value'] or [n] to pick one", c.XPath, len(hits), st.name)
		}
		if len(hits) == 0 {
			if c.State == Absent {
				return content, nil
			}
			if n != len(steps)-2 || st.index > 1 {
				return "", fmt.Errorf("xpath %q: there's no %s to put it in; Conn3x adds only the last element", c.XPath, st.name)
			}
			return addElement(b, cur, st, attr, c.Value), nil
		}
		cur = hits[0]
	}
	if attr != "" {
		return setAttr(b, cur, attr, c), nil
	}
	if c.State == Absent {
		if cur == root {
			return "", fmt.Errorf("xpath %q is the root element, which can't be taken out", c.XPath)
		}
		return string(dropElement(b, cur)), nil
	}
	if cur.hasChildElements {
		return "", fmt.Errorf("xpath %q has child elements; set its text only on an element that holds text", c.XPath)
	}
	if !cur.selfClosing {
		var have string
		d := xml.NewDecoder(bytes.NewReader(b[cur.startEnd:cur.end]))
		for {
			tok, err := d.Token()
			if err != nil {
				break
			}
			if cd, ok := tok.(xml.CharData); ok {
				have += string(cd)
			}
		}
		if have == c.Value {
			return content, nil
		}
		return string(b[:cur.startEnd]) + escapeXML(c.Value, false) + string(b[cur.end:]), nil
	}
	// <a/> becomes <a>value</a>, its attributes as they were.
	tag := strings.TrimRight(strings.TrimSuffix(strings.TrimRight(string(b[cur.start:cur.startEnd-1]), " \t\r\n"), "/"), " \t\r\n")
	return string(b[:cur.start]) + tag + ">" + escapeXML(c.Value, false) + "</" + qname(b, cur) + ">" + string(b[cur.startEnd:]), nil
}

// qname is the element's name as written, prefix included.
func qname(b []byte, e *xmlElem) string {
	tag := b[e.start+1 : e.startEnd]
	i := bytes.IndexAny(tag, " \t\r\n/>")
	return string(tag[:i])
}

// attrSpan finds an attribute in a start tag: where its leading space
// starts, where its quoted value starts and ends (quotes included), and
// where it ends, all relative to the tag. ok is false when it isn't there.
func attrSpan(tag []byte, name string) (lead, vstart, vend int, ok bool) {
	ws := func(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }
	i := 1
	for i < len(tag) && !ws(tag[i]) && tag[i] != '>' && tag[i] != '/' {
		i++
	}
	for i < len(tag) {
		l := i
		for i < len(tag) && ws(tag[i]) {
			i++
		}
		if i >= len(tag) || tag[i] == '>' || tag[i] == '/' {
			return 0, 0, 0, false
		}
		n := i
		for i < len(tag) && tag[i] != '=' && !ws(tag[i]) {
			i++
		}
		got := string(tag[n:i])
		for i < len(tag) && (ws(tag[i]) || tag[i] == '=') {
			i++
		}
		if i >= len(tag) || (tag[i] != '"' && tag[i] != '\'') {
			return 0, 0, 0, false
		}
		q, vs := tag[i], i
		i++
		for i < len(tag) && tag[i] != q {
			i++
		}
		i++
		if got == name {
			return l, vs, i, true
		}
	}
	return 0, 0, 0, false
}

func setAttr(b []byte, e *xmlElem, name string, c XMLValue) string {
	tag := b[e.start:e.startEnd]
	lead, vs, ve, ok := attrSpan(tag, name)
	if c.State == Absent {
		if !ok {
			return string(b)
		}
		return string(b[:e.start+lead]) + string(b[e.start+ve:])
	}
	if ok {
		for _, a := range e.attrs {
			if a.Name.Local == name && a.Value == c.Value {
				return string(b)
			}
		}
		q := tag[vs]
		val := escapeXML(c.Value, true)
		if q == '\'' {
			val = strings.ReplaceAll(val, "'", "&#39;")
		}
		return string(b[:e.start+vs+1]) + val + string(b[e.start+ve-1:])
	}
	// A new attribute goes after the last one, or after the name.
	at := e.startEnd - 1
	for at > e.start && (b[at-1] == '/' || b[at-1] == ' ' || b[at-1] == '\t' || b[at-1] == '\n' || b[at-1] == '\r') {
		at--
	}
	return string(b[:at]) + " " + name + `="` + escapeXML(c.Value, true) + `"` + string(b[at:])
}

// addElement puts a new last child in parent, indented as its last child
// is, with the predicate's attributes, and the text or attribute asked for.
func addElement(b []byte, parent *xmlElem, st xmlStep, attr, value string) string {
	el := "<" + st.name
	for _, a := range st.attrs {
		el += " " + a[0] + `="` + escapeXML(a[1], true) + `"`
	}
	if attr != "" {
		el += " " + attr + `="` + escapeXML(value, true) + `"/>`
	} else {
		el += ">" + escapeXML(value, false) + "</" + st.name + ">"
	}
	if parent.selfClosing {
		tag := strings.TrimRight(strings.TrimSuffix(strings.TrimRight(string(b[parent.start:parent.startEnd-1]), " \t\r\n"), "/"), " \t\r\n")
		return string(b[:parent.start]) + tag + ">" + el + "</" + qname(b, parent) + ">" + string(b[parent.startEnd:])
	}
	if len(parent.children) == 0 {
		return string(b[:parent.end]) + el + string(b[parent.end:])
	}
	last := parent.children[len(parent.children)-1]
	// The whitespace before the last child, from its line's start, is the
	// indent to copy.
	k := last.start
	for k > 0 && (b[k-1] == ' ' || b[k-1] == '\t') {
		k--
	}
	sep := ""
	if k > 0 && b[k-1] == '\n' {
		sep = "\n" + string(b[k:last.start])
	}
	return string(b[:last.endEnd]) + sep + el + string(b[last.endEnd:])
}

// dropElement takes out an element, with the line it was alone on.
func dropElement(b []byte, e *xmlElem) []byte {
	start, end := e.start, e.endEnd
	k := start
	for k > 0 && (b[k-1] == ' ' || b[k-1] == '\t') {
		k--
	}
	j := end
	for j < len(b) && (b[j] == ' ' || b[j] == '\t' || b[j] == '\r') {
		j++
	}
	if (k == 0 || b[k-1] == '\n') && j < len(b) && b[j] == '\n' {
		start, end = k, j+1
	}
	return append(append([]byte{}, b[:start]...), b[end:]...)
}
