// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// argEscape matches a backslash Ansible reads as an escape in a free-form
// line: before a quote or an =, or one parse_kv decodes, such as \n.
var argEscape = regexp.MustCompile(`\\[\\'"abfnrtvxuUN0-7=\n]`)

// splitArgs splits a free-form argument line, such as
// name={{ redis_daemon }} state=restarted, into words as Ansible's
// split_args does: whitespace inside {{ }}, {% %}, {# #} or quotes doesn't
// end a word. It reports false for a line with a block or a quote left
// open, or with an escape, which Ansible decodes and this doesn't.
func splitArgs(s string) ([]string, bool) {
	if argEscape.MatchString(s) {
		return nil, false
	}
	var words []string
	var quote byte
	depth := map[byte]int{} // open blocks by their second character
	start := -1
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		if quote == 0 && depth['{']+depth['%']+depth['#'] == 0 && unicode.IsSpace(r) {
			if start >= 0 {
				words = append(words, s[start:i])
				start = -1
			}
			i += n
			continue
		}
		if start < 0 {
			start = i
		}
		// As in Ansible, quotes count inside a block and blocks inside quotes.
		switch c := s[i]; {
		case c == '"' || c == '\'':
			switch quote {
			case 0:
				quote = c
			case c:
				quote = 0
			}
		case i+1 < len(s) && c == '{' && (s[i+1] == '{' || s[i+1] == '%' || s[i+1] == '#'):
			depth[s[i+1]]++
			n = 2
		case i+1 < len(s) && s[i+1] == '}' && (c == '}' || c == '%' || c == '#'):
			if c == '}' {
				c = '{'
			}
			if depth[c]--; depth[c] < 0 {
				return nil, false
			}
			n = 2
		}
		i += n
	}
	if quote != 0 || depth['{']+depth['%']+depth['#'] != 0 {
		return nil, false
	}
	if start >= 0 {
		words = append(words, s[start:])
	}
	return words, true
}

// unquoteArg takes the outer quotes off a free-form value, as Ansible's
// unquote does.
func unquoteArg(s string) string {
	if len(s) > 1 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

// commandWords splits a command or shell line as Ansible's parse_kv does,
// or reports false for a line splitArgs refuses or with whitespace other
// than spaces and newlines, which Ansible doesn't split at and splitArgs
// does.
func commandWords(s string) ([]string, bool) {
	if strings.IndexFunc(s, func(r rune) bool { return unicode.IsSpace(r) && r != ' ' && r != '\n' }) >= 0 {
		return nil, false
	}
	return splitArgs(s)
}

// commandArgs takes the options Ansible's parse_kv pulls out of a command or
// shell line, the inlineArgs, and returns the line left and the options. As
// in Ansible, a word goes with the whitespace after it, and any other k=v
// word stays in the command. A line commandWords can't split comes back as
// it is.
func commandArgs(v *yaml.Node) (*yaml.Node, map[string]*yaml.Node) {
	words, ok := commandWords(v.Value)
	if !ok {
		return v, nil
	}
	opts := map[string]*yaml.Node{}
	var rest strings.Builder
	s := v.Value
	for _, w := range words {
		i := strings.Index(s, w)
		k, val, _ := strings.Cut(w, "=")
		if !inlineArgs[k] {
			rest.WriteString(s[:i+len(w)])
			s = s[i+len(w):]
			continue
		}
		opts[k] = &yaml.Node{Kind: yaml.ScalarNode, Value: unquoteArg(strings.TrimSpace(val)), Line: v.Line}
		rest.WriteString(s[:i])
		s = strings.TrimLeft(s[i+len(w):], " \n")
	}
	if len(opts) == 0 {
		return v, nil
	}
	rest.WriteString(s)
	raw := *v
	raw.Value = strings.TrimSpace(rest.String())
	// What's left is text to Ansible, never retyped as YAML 1.1.
	raw.Style = yaml.DoubleQuotedStyle
	return &raw, opts
}
