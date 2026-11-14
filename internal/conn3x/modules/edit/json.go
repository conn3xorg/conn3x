// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package edit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

// JSONValue is one value in a JSON file, at a path such as server.port or
// servers[0].name, which should or should not be there.
type JSONValue struct {
	Path  string
	Value string // JSON, as jsonencode writes it
	State State
}

// jsonStep is one step of a path: an object key, or an array index.
type jsonStep struct {
	key   string
	index int // -1 for a key
}

var pathStep = regexp.MustCompile(`^([^.\[\]]+)((?:\[[0-9]+\])*)$`)

func (c JSONValue) steps() ([]jsonStep, error) {
	if c.Path == "" {
		return nil, errors.New("path must name a value, such as server.port")
	}
	var out []jsonStep
	for _, part := range strings.Split(c.Path, ".") {
		m := pathStep.FindStringSubmatch(part)
		if m == nil {
			return nil, fmt.Errorf("path %q: %q isn't a key, optionally followed by [index]", c.Path, part)
		}
		out = append(out, jsonStep{key: m[1], index: -1})
		for _, ix := range regexp.MustCompile(`[0-9]+`).FindAllString(m[2], -1) {
			n, _ := strconv.Atoi(ix)
			out = append(out, jsonStep{index: n})
		}
	}
	return out, nil
}

// Validate checks a JSONValue before anything reaches the host.
func (c JSONValue) Validate() error {
	if _, err := c.steps(); err != nil {
		return err
	}
	switch c.State {
	case Present, "":
		if !json.Valid([]byte(c.Value)) {
			return fmt.Errorf("value %q isn't JSON; write it with jsonencode, such as jsonencode(8080) or jsonencode(\"info\")", c.Value)
		}
	case Absent:
	default:
		return fmt.Errorf("state must be %q or %q, not %q", Present, Absent, c.State)
	}
	return nil
}

// span is where a value sits in the document, and, for an object, its
// members; for an array, its elements.
type span struct {
	start, end int
	members    []member // object
	elems      []span   // array
	object     bool
	array      bool
}

type member struct {
	key              string
	keyStart, valEnd int
	val              span
}

type scanner struct {
	b []byte
}

func (s *scanner) ws(i int) int {
	for i < len(s.b) && (s.b[i] == ' ' || s.b[i] == '\t' || s.b[i] == '\n' || s.b[i] == '\r') {
		i++
	}
	return i
}

// value scans the value starting at i, after any whitespace.
func (s *scanner) value(i int) (span, error) {
	i = s.ws(i)
	if i >= len(s.b) {
		return span{}, errors.New("unexpected end of JSON")
	}
	switch s.b[i] {
	case '{':
		sp := span{start: i, object: true}
		j := s.ws(i + 1)
		if j < len(s.b) && s.b[j] == '}' {
			sp.end = j + 1
			return sp, nil
		}
		for {
			j = s.ws(j)
			ks := j
			ke, err := s.str(j)
			if err != nil {
				return span{}, err
			}
			var key string
			if err := json.Unmarshal(s.b[ks:ke], &key); err != nil {
				return span{}, err
			}
			j = s.ws(ke)
			if j >= len(s.b) || s.b[j] != ':' {
				return span{}, fmt.Errorf("expected : at offset %d", j)
			}
			v, err := s.value(j + 1)
			if err != nil {
				return span{}, err
			}
			sp.members = append(sp.members, member{key: key, keyStart: ks, valEnd: v.end, val: v})
			j = s.ws(v.end)
			if j < len(s.b) && s.b[j] == ',' {
				j++
				continue
			}
			if j < len(s.b) && s.b[j] == '}' {
				sp.end = j + 1
				return sp, nil
			}
			return span{}, fmt.Errorf("expected , or } at offset %d", j)
		}
	case '[':
		sp := span{start: i, array: true}
		j := s.ws(i + 1)
		if j < len(s.b) && s.b[j] == ']' {
			sp.end = j + 1
			return sp, nil
		}
		for {
			v, err := s.value(j)
			if err != nil {
				return span{}, err
			}
			sp.elems = append(sp.elems, v)
			j = s.ws(v.end)
			if j < len(s.b) && s.b[j] == ',' {
				j++
				continue
			}
			if j < len(s.b) && s.b[j] == ']' {
				sp.end = j + 1
				return sp, nil
			}
			return span{}, fmt.Errorf("expected , or ] at offset %d", j)
		}
	case '"':
		e, err := s.str(i)
		return span{start: i, end: e}, err
	default:
		// A number, true, false or null runs to the next delimiter.
		j := i
		for j < len(s.b) && !strings.ContainsRune(",}] \t\r\n", rune(s.b[j])) {
			j++
		}
		return span{start: i, end: j}, nil
	}
}

func (s *scanner) str(i int) (int, error) {
	if i >= len(s.b) || s.b[i] != '"' {
		return 0, fmt.Errorf("expected a string at offset %d", i)
	}
	for j := i + 1; j < len(s.b); j++ {
		switch s.b[j] {
		case '\\':
			j++
		case '"':
			return j + 1, nil
		}
	}
	return 0, errors.New("unterminated string")
}

// ApplyJSONValue returns content with the value set, or taken out, and
// every other byte as it was. A value that's already equal, however it's
// written, is left alone.
func ApplyJSONValue(content string, c JSONValue) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	steps, _ := c.steps()
	if strings.TrimSpace(content) == "" {
		if c.State == Absent {
			return content, nil
		}
		content = "{}\n"
	}
	b := []byte(content)
	if !json.Valid(b) {
		return "", errors.New("the file isn't valid JSON")
	}
	s := &scanner{b: b}
	cur, err := s.value(0)
	if err != nil {
		return "", err
	}
	for n, st := range steps {
		last := n == len(steps)-1
		if st.index >= 0 {
			if !cur.array {
				return "", fmt.Errorf("path %q: [%d] is on something that isn't an array", c.Path, st.index)
			}
			if st.index >= len(cur.elems) {
				if c.State == Absent {
					return content, nil
				}
				return "", fmt.Errorf("path %q: the array has %d elements, so [%d] isn't there to set", c.Path, len(cur.elems), st.index)
			}
			if last {
				return c.replaceOrDrop(b, cur, st.index, -1)
			}
			cur = cur.elems[st.index]
			continue
		}
		if !cur.object {
			return "", fmt.Errorf("path %q: %q is on something that isn't an object", c.Path, st.key)
		}
		found := -1
		for i, m := range cur.members {
			if m.key == st.key {
				found = i
			}
		}
		if found < 0 {
			if c.State == Absent {
				return content, nil
			}
			// Add the key, with whatever's left of the path made as objects.
			val := []byte(c.Value)
			for k := len(steps) - 1; k > n; k-- {
				if steps[k].index >= 0 {
					return "", fmt.Errorf("path %q: %q isn't there, and Conn3x doesn't make arrays", c.Path, st.key)
				}
				kb, _ := json.Marshal(steps[k].key)
				val = append(append(append([]byte("{"), kb...), ':'), append(compact(val), '}')...)
			}
			return string(insertMember(b, cur, st.key, val)), nil
		}
		if last {
			return c.replaceOrDrop(b, cur, -1, found)
		}
		cur = cur.members[found].val
	}
	return content, nil
}

func compact(v []byte) []byte {
	var out bytes.Buffer
	if json.Compact(&out, v) != nil {
		return v
	}
	return out.Bytes()
}

func jsonEqual(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

// replaceOrDrop sets or takes out an array element (elem) or an object
// member (mem) of parent.
func (c JSONValue) replaceOrDrop(b []byte, parent span, elem, mem int) (string, error) {
	var target span
	if elem >= 0 {
		target = parent.elems[elem]
	} else {
		target = parent.members[mem].val
	}
	if c.State == Absent {
		if elem >= 0 {
			return "", fmt.Errorf("path %q ends in an array index; Conn3x takes out keys, not array elements", c.Path)
		}
		return string(dropMember(b, parent, mem)), nil
	}
	if jsonEqual(b[target.start:target.end], []byte(c.Value)) {
		return string(b), nil
	}
	out := append([]byte{}, b[:target.start]...)
	out = append(out, compact([]byte(c.Value))...)
	return string(append(out, b[target.end:]...)), nil
}

// insertMember adds "key": val to obj, after its last member, indented as
// that member is.
func insertMember(b []byte, obj span, key string, val []byte) []byte {
	kb, _ := json.Marshal(key)
	if len(obj.members) == 0 {
		out := append([]byte{}, b[:obj.start+1]...)
		out = append(out, kb...)
		out = append(out, ": "...)
		out = append(out, val...)
		return append(out, b[obj.end-1:]...)
	}
	last := obj.members[len(obj.members)-1]
	// The whitespace before the last member's key is the indent to copy.
	k := last.keyStart
	for k > 0 && (b[k-1] == ' ' || b[k-1] == '\t') {
		k--
	}
	indent := string(b[k:last.keyStart])
	sep := ", "
	if k > 0 && b[k-1] == '\n' {
		sep = ",\n" + indent
	}
	colon := ": "
	if bytes.Contains(b[last.keyStart:last.val.start], []byte(":")) && !bytes.Contains(b[last.keyStart:last.val.start], []byte(": ")) {
		colon = ":"
	}
	out := append([]byte{}, b[:last.valEnd]...)
	out = append(out, sep...)
	out = append(out, kb...)
	out = append(out, colon...)
	out = append(out, val...)
	return append(out, b[last.valEnd:]...)
}

// dropMember takes out obj's member i, with the comma and the whitespace
// that went with it.
func dropMember(b []byte, obj span, i int) []byte {
	m := obj.members[i]
	start, end := m.keyStart, m.valEnd
	if i+1 < len(obj.members) {
		// Up to the next key: its comma and line go with this member.
		end = obj.members[i+1].keyStart
		k := m.keyStart
		for k > 0 && (b[k-1] == ' ' || b[k-1] == '\t') {
			k--
		}
		start = k
		for end > 0 && (b[end-1] == ' ' || b[end-1] == '\t') {
			end--
		}
	} else if i > 0 {
		// The last one: from the end of the one before, comma included.
		start = obj.members[i-1].valEnd
	} else {
		// The only one: leave {} with what was inside the braces' edges.
		start, end = obj.start+1, obj.end-1
	}
	out := append([]byte{}, b[:start]...)
	return append(out, b[end:]...)
}
