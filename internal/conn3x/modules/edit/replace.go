// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package edit

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Replace swaps every match of a regexp in a file. ^ and $ match at each
// line, and With can use $1, ${1} and ${name}, with $$ for a dollar sign.
type Replace struct {
	Regexp string
	With   string
}

var templateRef = regexp.MustCompile(`\$(?:\$|([A-Za-z0-9_]+)|\{([A-Za-z0-9_]+)\})`)

func (r Replace) compile() (*regexp.Regexp, error) {
	if r.Regexp == "" {
		return nil, errors.New("regexp is required")
	}
	re, err := regexp.Compile("(?m)" + r.Regexp)
	if err != nil {
		return nil, fmt.Errorf("regexp: %w", err)
	}
	return re, nil
}

// Validate checks a Replace before anything is edited. A reference to a
// group that doesn't exist would expand to nothing and lose text, so it's
// an error here. Without references, the replacement must survive its own
// regexp, or the file could never settle.
func (r Replace) Validate() error {
	re, err := r.compile()
	if err != nil {
		return err
	}
	names := map[string]bool{}
	for i, n := range re.SubexpNames() {
		names[strconv.Itoa(i)] = true
		if n != "" {
			names[n] = true
		}
	}
	literal := true
	for _, m := range templateRef.FindAllStringSubmatch(r.With, -1) {
		if m[0] == "$$" {
			continue
		}
		literal = false
		if ref := m[1] + m[2]; !names[ref] {
			return fmt.Errorf("replace: %s isn't a group in regexp; to follow a group with letters or digits, write ${1}", m[0])
		}
	}
	if text := strings.ReplaceAll(r.With, "$$", "$"); literal && re.ReplaceAllString(text, r.With) != text {
		return r.neverSettles()
	}
	return nil
}

func (r Replace) neverSettles() error {
	return fmt.Errorf("regexp %q still matches after it's replaced, so every plan would change the file again; make it match only the old text", r.Regexp)
}

// ApplyReplace returns content with every match replaced. It refuses a
// result the same edit would change again.
func ApplyReplace(content string, r Replace) (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	re, err := r.compile()
	if err != nil {
		return "", err
	}
	edited := re.ReplaceAllString(content, r.With)
	if re.ReplaceAllString(edited, r.With) != edited {
		return "", r.neverSettles()
	}
	return edited, nil
}
