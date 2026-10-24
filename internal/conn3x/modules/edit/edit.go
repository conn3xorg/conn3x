// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package edit changes part of a text file: one line, or a marked block of
// lines. The edits are pure functions of the file's content; the caller
// reads and writes the file through the file module, so writes stay atomic
// and keep the file's mode, owner and SELinux label.
package edit

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// State is whether the line or block should be in the file.
type State string

const (
	Present State = "present"
	Absent  State = "absent"
)

// bof and eof are the special anchors for insert_before and insert_after.
const (
	bof = "BOF"
	eof = "EOF"
)

// Line is one line that should, or should not, be in a file.
type Line struct {
	Line         string
	Regexp       string // lines to replace, or to remove when absent
	InsertAfter  string // regexp, or "EOF" (the default)
	InsertBefore string // regexp, or "BOF"
	State        State  // default Present
}

// Validate checks a Line before anything is edited.
func (l Line) Validate() error {
	switch l.State {
	case "", Present, Absent:
	default:
		return fmt.Errorf("state must be %q or %q, not %q", Present, Absent, l.State)
	}
	if l.State != Absent && l.Line == "" {
		return errors.New("line is required")
	}
	if l.State == Absent && l.Line == "" && l.Regexp == "" {
		return errors.New("line or regexp is required")
	}
	if strings.Contains(l.Line, "\n") {
		return errors.New("line must be a single line; use a block for several")
	}
	if l.InsertAfter != "" && l.InsertBefore != "" {
		return errors.New("set insert_after or insert_before, not both")
	}
	for name, re := range map[string]string{"regexp": l.Regexp, "insert_after": l.InsertAfter, "insert_before": l.InsertBefore} {
		if re != "" && re != bof && re != eof {
			if _, err := regexp.Compile(re); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	return nil
}

// ApplyLine returns content with the line edit applied.
func ApplyLine(content string, l Line) (string, error) {
	if err := l.Validate(); err != nil {
		return "", err
	}
	lines, final := split(content)
	var re *regexp.Regexp
	if l.Regexp != "" {
		re = regexp.MustCompile(l.Regexp)
	}
	matches := func(s string) bool {
		if re != nil {
			return re.MatchString(s)
		}
		return s == l.Line
	}

	if l.State == Absent {
		kept := lines[:0:0]
		for _, s := range lines {
			if !matches(s) {
				kept = append(kept, s)
			}
		}
		return join(kept, final), nil
	}

	if re != nil {
		for i := len(lines) - 1; i >= 0; i-- {
			if re.MatchString(lines[i]) {
				lines[i] = l.Line
				return join(lines, final), nil
			}
		}
	}
	for _, s := range lines {
		if s == l.Line {
			return join(lines, final), nil
		}
	}
	return join(insert(lines, []string{l.Line}, l.InsertAfter, l.InsertBefore), true), nil
}

// insert places new lines by anchor: after the last match of after, before
// the first match of before, at the start for "BOF", otherwise at the end.
func insert(lines, add []string, after, before string) []string {
	at := len(lines)
	switch {
	case before == bof:
		at = 0
	case before != "":
		re := regexp.MustCompile(before)
		for i, s := range lines {
			if re.MatchString(s) {
				at = i
				break
			}
		}
	case after != "" && after != eof:
		re := regexp.MustCompile(after)
		for i := len(lines) - 1; i >= 0; i-- {
			if re.MatchString(lines[i]) {
				at = i + 1
				break
			}
		}
	}
	out := make([]string, 0, len(lines)+len(add))
	out = append(out, lines[:at]...)
	out = append(out, add...)
	return append(out, lines[at:]...)
}

// DefaultMarker brackets a managed block; {mark} becomes BEGIN or END.
const DefaultMarker = "# {mark} CONN3X MANAGED BLOCK"

// Block is a marked block of lines that should, or should not, be in a file.
type Block struct {
	Content      string
	Marker       string // with {mark}; default DefaultMarker
	InsertAfter  string
	InsertBefore string
	State        State
}

// Validate checks a Block before anything is edited.
func (b Block) Validate() error {
	switch b.State {
	case "", Present, Absent:
	default:
		return fmt.Errorf("state must be %q or %q, not %q", Present, Absent, b.State)
	}
	if b.Marker != "" && !strings.Contains(b.Marker, "{mark}") {
		return errors.New("marker must contain {mark}")
	}
	if b.InsertAfter != "" && b.InsertBefore != "" {
		return errors.New("set insert_after or insert_before, not both")
	}
	for name, re := range map[string]string{"insert_after": b.InsertAfter, "insert_before": b.InsertBefore} {
		if re != "" && re != bof && re != eof {
			if _, err := regexp.Compile(re); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	return nil
}

// ApplyBlock returns content with the block inserted, replaced or removed.
func ApplyBlock(content string, b Block) (string, error) {
	if err := b.Validate(); err != nil {
		return "", err
	}
	marker := b.Marker
	if marker == "" {
		marker = DefaultMarker
	}
	begin := strings.ReplaceAll(marker, "{mark}", "BEGIN")
	end := strings.ReplaceAll(marker, "{mark}", "END")

	lines, final := split(content)
	start, stop := -1, -1
	for i, s := range lines {
		if s == begin && start < 0 {
			start = i
		} else if s == end && start >= 0 {
			stop = i
			break
		}
	}
	if start >= 0 && stop < 0 {
		return "", fmt.Errorf("found %q without a matching %q; fix the file by hand first", begin, end)
	}

	var block []string
	if b.State != Absent {
		block = append([]string{begin}, strings.Split(strings.TrimRight(b.Content, "\n"), "\n")...)
		block = append(block, end)
	}
	if start >= 0 {
		out := append(append(append([]string{}, lines[:start]...), block...), lines[stop+1:]...)
		return join(out, final || len(block) > 0), nil
	}
	if b.State == Absent {
		return content, nil
	}
	return join(insert(lines, block, b.InsertAfter, b.InsertBefore), true), nil
}

// split breaks content into lines and reports whether it ended with a newline.
func split(content string) ([]string, bool) {
	if content == "" {
		return nil, false
	}
	final := strings.HasSuffix(content, "\n")
	return strings.Split(strings.TrimSuffix(content, "\n"), "\n"), final
}

func join(lines []string, final bool) string {
	if len(lines) == 0 {
		return ""
	}
	s := strings.Join(lines, "\n")
	if final {
		s += "\n"
	}
	return s
}
