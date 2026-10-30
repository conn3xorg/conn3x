// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"fmt"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"

	"github.com/zclconf/go-cty/cty"
	"gopkg.in/yaml.v3"

	"github.com/opentofu/opentofu/internal/conn3x/modules/edit"
)

// YAML 1.1, which Ansible reads, turns unquoted yes into True, 1.10 into 1.1
// and 010 into 8, and yaml.v3 hands the original text to the converter. So
// the only unquoted values trusted to stay as written are plain words and
// plain whole numbers.
var (
	yamlWord    = regexp.MustCompile(`(?i)^(|~|yes|no|on|off|true|false|null)$`)
	yamlNumeric = regexp.MustCompile(`^[-+.0-9]`)
	plainInt    = regexp.MustCompile(`^(0|-?[1-9][0-9]*)$`)
)

// text reads an argument that has to reach the host exactly as Ansible would
// see it, and refuses it when it can't be sure of that.
func (in *input) text(key string) string {
	n, ok := in.args[key]
	if !ok {
		return ""
	}
	v := in.str(key)
	quoted := n.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle|yaml.LiteralStyle|yaml.FoldedStyle) != 0
	templated := strings.Contains(n.Value, "{{")
	if (!quoted || templated) && (yamlWord.MatchString(v) || (yamlNumeric.MatchString(v) && !plainInt.MatchString(v))) {
		in.fail(fmt.Sprintf("has %s %q, which Ansible may read as something other than that text; quote it in the playbook and in any variable it comes from", key, v))
	}
	if strings.Contains(v, "{#") {
		in.fail(key + " has a Jinja comment, which Ansible would strip")
	}
	return v
}

// exactTask is what a task needs before its text can be trusted at all.
func exactTask(in *input) string {
	if in.has("_raw") {
		return "is written as key=value text; write its arguments as YAML so the converter can read them exactly"
	}
	if in.loop {
		return "loops, which the converter can't prove the same here; write one task for each"
	}
	return ""
}

func iniFileModule(in *input) ([]step, string) {
	if why := exactTask(in); why != "" {
		return nil, why
	}
	st := in.state("present", "present", "absent")
	if !in.has("option") {
		return nil, "changes a whole section; an ini step changes one option"
	}
	c := edit.INI{Option: in.text("option"), Value: in.text("value"), NoExtraSpaces: in.bool("no_extra_spaces", false), Uncomment: in.bool("modify_inactive_option", true) && st == "present"}
	attrs := []attr{s("path", in.str("path", "dest"))}
	if n, ok := in.args["section"]; ok && n.ShortTag() == "!!null" {
		in.ignore("section")
	} else if ok {
		if c.Section = in.text("section"); c.Section == "" {
			return nil, "has an empty section; leave section out to put the option before the first section"
		}
		attrs = append(attrs, s("section", c.Section))
	}
	attrs = append(attrs, s("option", c.Option))
	create := in.bool("create", true)
	switch st {
	case "present":
		if !in.has("value") {
			return nil, "sets an option with no value, which the converter can't translate"
		}
		attrs = append(attrs, s("value", c.Value))
		if create {
			attrs = append(attrs, attr{key: "create", val: cty.True})
		}
	case "absent":
		if in.has("value") {
			return nil, "sets value with state: absent; an ini step removes the option whatever its value"
		}
		if !create {
			return nil, "sets create: no with state: absent, so Ansible fails on a missing file; an ini step has nothing to remove and carries on"
		}
		c.State = edit.Absent
		attrs = append(attrs, s("state", st))
	}
	if c.NoExtraSpaces {
		attrs = append(attrs, attr{key: "no_extra_spaces", val: cty.True})
	}
	if c.Uncomment {
		attrs = append(attrs, attr{key: "uncomment", val: cty.True})
	}
	if !in.bool("exclusive", true) {
		return nil, "sets exclusive: no; an ini step keeps one line for each option"
	}
	for _, key := range []string{"allow_no_value", "ignore_spaces", "backup"} {
		if in.bool(key, false) {
			return nil, "sets " + key + ", which an ini step doesn't have"
		}
	}
	if err := c.Validate(); err != nil {
		return nil, "can't be an ini step: " + err.Error()
	}
	var notes []string
	if !in.bool("follow", false) {
		notes = append(notes, "Without follow, Ansible replaces a symlink at this path with a file; Conn3x writes through the link.")
	}
	notes = append(notes, "Ansible rewrites Windows line endings to Unix ones here; Conn3x keeps them.")
	return one("ini", attrs, notes...)
}

func replaceModule(in *input) ([]step, string) {
	if why := exactTask(in); why != "" {
		return nil, why
	}
	if !in.has("regexp") {
		return nil, "has no regexp"
	}
	pattern, with := in.text("regexp"), in.text("replace")
	if in.problem != "" {
		return nil, in.problem
	}
	if why := unprovableRegexp(pattern); why != "" {
		return nil, why
	}
	tmpl, why := goTemplate(with, regexp.MustCompile(pattern))
	if why != "" {
		return nil, why
	}
	if e := strings.ToLower(in.str("encoding")); in.has("encoding") && e != "utf-8" && e != "utf8" {
		return nil, fmt.Sprintf("sets encoding %q; Conn3x edits files as UTF-8", e)
	}
	if in.bool("backup", false) {
		return nil, "sets backup, which a replace step doesn't have"
	}
	if err := (edit.Replace{Regexp: pattern, With: tmpl}).Validate(); err != nil {
		return nil, "never settles or can't be a replace step: " + err.Error()
	}
	return one("replace", []attr{s("path", in.str("path", "dest", "destfile", "name")), s("regexp", pattern), s("replace", tmpl)})
}

// unprovableRegexp says why a Python regexp might not match what the same
// text matches in Go, or "" when it can't differ. It lists what is safe, not
// what's known to differ, so anything unforeseen is refused.
func unprovableRegexp(p string) string {
	refuse := func(what, why string) string {
		return fmt.Sprintf("has a regexp using %s, %s; rewrite it without that or use a guarded command step", what, why)
	}
	inClass := false
	for i := 0; i < len(p); i++ {
		c := p[i]
		next := byte(0)
		if i+1 < len(p) {
			next = p[i+1]
		}
		switch {
		case c == '\\':
			if (next >= '0' && next <= '9') || (next >= 'a' && next <= 'z') || (next >= 'A' && next <= 'Z') {
				if !strings.ContainsRune("tnrfvaA", rune(next)) {
					return refuse(`\`+string(next), "which means something else in Python, such as Unicode rather than ASCII classes, or a backreference Go doesn't have")
				}
			}
			i++
		case inClass:
			if c == '[' && next == ':' {
				return refuse("[:", "a POSIX class in Go and plain characters in Python")
			}
			inClass = c != ']'
		case c == '[':
			inClass = true
			if next == '^' {
				i++
				next = 0
				if i+1 < len(p) {
					next = p[i+1]
				}
			}
			if next == ']' {
				i++
			}
		case c == '(' && next == '?':
			if !strings.HasPrefix(p[i:], "(?:") && !strings.HasPrefix(p[i:], "(?P<") {
				return refuse(p[i:min(i+3, len(p))], "a lookaround, flag or group form that Go lacks or reads differently")
			}
		case c == '{' && next == ',':
			return refuse("{,n}", "a repeat in Python and plain text in Go")
		}
	}
	re, err := syntax.Parse(p, syntax.Perl)
	if err != nil {
		return "has a regexp Go can't compile: " + err.Error()
	}
	if nullable(re) {
		return refuse("a pattern that can match nothing", "where Python and Go replace different empty matches")
	}
	if loopsOnEmpty(re) {
		return refuse("a repeat of something that can match nothing", "where Python and Go can capture differently")
	}
	return ""
}

func nullable(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpLiteral, syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL, syntax.OpNoMatch:
		return false
	case syntax.OpCapture, syntax.OpPlus:
		return nullable(re.Sub[0])
	case syntax.OpRepeat:
		return re.Min == 0 || nullable(re.Sub[0])
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			if !nullable(sub) {
				return false
			}
		}
		return true
	case syntax.OpAlternate:
		for _, sub := range re.Sub {
			if nullable(sub) {
				return true
			}
		}
		return false
	}
	return true // stars, optionals and anchors
}

func loopsOnEmpty(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat:
		if nullable(re.Sub[0]) {
			return true
		}
	}
	for _, sub := range re.Sub {
		if loopsOnEmpty(sub) {
			return true
		}
	}
	return false
}

var groupName = regexp.MustCompile(`^(0|[1-9][0-9]*|[A-Za-z_][A-Za-z0-9_]*)$`)

// goTemplate rewrites a Python replacement for Go: backreferences become
// ${n}, and a dollar sign, plain text in Python, becomes $$. A reference to
// a group that isn't there is an error in Python, and only blank in Go.
func goTemplate(py string, re *regexp.Regexp) (string, string) {
	escapes := map[byte]string{'\\': `\`, 'n': "\n", 't': "\t", 'r': "\r", 'f': "\f", 'v': "\v", 'a': "\a", 'b': "\b"}
	var b strings.Builder
	ref := func(name string) string {
		n, err := strconv.Atoi(name)
		if (err == nil && n > re.NumSubexp()) || (err != nil && re.SubexpIndex(name) < 0) {
			return fmt.Sprintf(`has a replace naming group %s, which regexp doesn't have, so Ansible fails`, name)
		}
		b.WriteString("${" + name + "}")
		return ""
	}
	for i := 0; i < len(py); i++ {
		switch c := py[i]; {
		case c == '$':
			b.WriteString("$$")
		case c != '\\':
			b.WriteByte(c)
		case i+1 == len(py):
			return "", `has a replace ending in a lone \, which Ansible fails on`
		default:
			i++
			next := py[i]
			if v, ok := escapes[next]; ok {
				b.WriteString(v)
				continue
			}
			var name string
			switch {
			case next >= '1' && next <= '9' && (i+1 == len(py) || py[i+1] < '0' || py[i+1] > '9'):
				name = string(next)
			case next == 'g' && i+1 < len(py) && py[i+1] == '<' && strings.IndexByte(py[i:], '>') > 0:
				end := i + strings.IndexByte(py[i:], '>')
				name = py[i+2 : end]
				i = end
				if !groupName.MatchString(name) {
					return "", fmt.Sprintf(`has a replace with the reference \g<%s>, which the converter can't read`, name)
				}
			default:
				return "", fmt.Sprintf(`has a replace with \%c, which the converter can't prove means the same in Conn3x`, next)
			}
			if why := ref(name); why != "" {
				return "", why
			}
		}
	}
	return b.String(), ""
}
