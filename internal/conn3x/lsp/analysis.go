// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package lsp

import (
	"regexp"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// The same reading of a circuit file as the VS Code extension's lib.js: by
// text, not by parsing, so it works on a file that's half written.

var (
	blockHead  = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_-]*)(?:\s+"[^"\n]*")*\s*$`)
	notBlock   = regexp.MustCompile(`[=:(\[,]\s*$`)
	heredoc    = regexp.MustCompile(`^<<-?([A-Za-z_][A-Za-z0-9_]*)\n`)
	assignment = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=`)
)

// blockPath returns the names of the blocks enclosing the end of text, from
// the outside in: [circuit step file] inside a step's file block. A brace
// that doesn't open a named block, such as a map, is "{". Strings, comments
// and heredocs are skipped, so braces in them don't count.
func blockPath(text string) []string {
	var stack []string
	lineStart := 0
	for i := 0; i < len(text); {
		c := text[i]
		switch {
		case c == '\n':
			lineStart = i + 1
			i++
			continue
		case c == '#' || (c == '/' && i+1 < len(text) && text[i+1] == '/'):
			if end := strings.IndexByte(text[i:], '\n'); end >= 0 {
				i += end
			} else {
				i = len(text)
			}
			continue
		case c == '/' && i+1 < len(text) && text[i+1] == '*':
			if end := strings.Index(text[i+2:], "*/"); end >= 0 {
				i += 2 + end + 2
			} else {
				i = len(text)
			}
			continue
		case c == '"':
			i = skipString(text, i+1)
			continue
		case c == '<' && i+1 < len(text) && text[i+1] == '<':
			if m := heredoc.FindStringSubmatch(text[i:]); m != nil {
				body := i + len(m[0]) - 1
				end := regexp.MustCompile(`\n\s*` + m[1] + `\b`).FindStringIndex(text[body:])
				if end != nil {
					i = body + end[1]
				} else {
					i = len(text)
				}
				continue
			}
		case c == '{':
			line := text[lineStart:i]
			if m := blockHead.FindStringSubmatchIndex(line); m != nil && !notBlock.MatchString(line[:m[0]]) {
				stack = append(stack, line[m[2]:m[3]])
			} else {
				stack = append(stack, "{")
			}
		case c == '}':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
		i++
	}
	return stack
}

// skipString returns the index after the string whose opening quote is just
// before i, minding escapes and ${ } templates.
func skipString(text string, i int) int {
	depth := 0
	for i < len(text) {
		c := text[i]
		switch {
		case c == '\\':
			i += 2
			continue
		case c == '$' && i+1 < len(text) && text[i+1] == '{':
			depth++
			i += 2
			continue
		case c == '}' && depth > 0:
			depth--
		case c == '"' && depth == 0:
			return i + 1
		case c == '\n' && depth == 0:
			return i // unterminated: stop at the line
		}
		i++
	}
	return i
}

// stepBlocks are the blocks whose direct children are step modules.
var stepBlocks = map[string]bool{"step": true, "prereq": true}

// place is what the cursor is inside: a step, where a module goes, or a
// module or one of its nested blocks, whose arguments go there.
type place struct {
	step   bool
	module string
	block  *block
}

// where reads path. ok is false anywhere else.
func where(path []string, cat catalog) (place, bool) {
	for i := len(path) - 1; i >= 0; i-- {
		if !stepBlocks[path[i]] {
			continue
		}
		inner := path[i+1:]
		if len(inner) == 0 {
			return place{step: true}, true
		}
		b := cat[inner[0]]
		if b == nil {
			return place{}, false
		}
		for _, name := range inner[1:] {
			if b = b.blocks[name]; b == nil {
				return place{}, false
			}
		}
		return place{module: inner[0], block: b}, true
	}
	return place{}, false
}

// argsSet lists the arguments already written in the innermost block text
// ends inside, so completion doesn't offer them again.
func argsSet(text string) map[string]bool {
	depth := 0
	for i := len(text) - 1; i >= 0; i-- {
		switch text[i] {
		case '}':
			depth++
		case '{':
			if depth > 0 {
				depth--
				continue
			}
			set := map[string]bool{}
			d := 0
			for _, line := range strings.Split(text[i+1:], "\n") {
				if d == 0 {
					if m := assignment.FindStringSubmatch(line); m != nil {
						set[m[1]] = true
					}
				}
				for _, ch := range line {
					switch ch {
					case '{', '[', '(':
						d++
					case '}', ']', ')':
						d--
					}
				}
			}
			return set
		}
	}
	return map[string]bool{}
}

// offset turns an LSP position, a line and a UTF-16 column, into a byte
// offset in text, clamped to the text.
func offset(text string, line, char int) int {
	i := 0
	for ; line > 0; line-- {
		nl := strings.IndexByte(text[i:], '\n')
		if nl < 0 {
			return len(text)
		}
		i += nl + 1
	}
	for units := 0; i < len(text) && text[i] != '\n' && units < char; {
		r, size := utf8.DecodeRuneInString(text[i:])
		units += len(utf16.Encode([]rune{r}))
		i += size
	}
	return i
}

// wordAt is the identifier around byte offset i.
func wordAt(text string, i int) string {
	isWord := func(b byte) bool {
		return b == '_' || b == '-' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
	}
	start, end := i, i
	for start > 0 && isWord(text[start-1]) {
		start--
	}
	for end < len(text) && isWord(text[end]) {
		end++
	}
	return text[start:end]
}
