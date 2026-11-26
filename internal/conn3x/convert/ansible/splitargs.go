// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"regexp"
	"unicode"
	"unicode/utf8"
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
