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
	// After and Before, when set, limit the edit to one section of the
	// file, as Ansible's replace does: from the first match of After to
	// the nearest match of Before after it, or to the end of the file, or
	// from the start to the last match of Before. . matches a line break
	// in them.
	After, Before string
}

// sectionGroup names the section in the pattern After and Before make.
const sectionGroup = "conn3xsection"

// sectionRegexp is the pattern that finds the section, or nil without
// After or Before.
func (r Replace) sectionRegexp() (*regexp.Regexp, error) {
	if r.After == "" && r.Before == "" {
		return nil, nil
	}
	for arg, p := range map[string]string{"after": r.After, "before": r.Before} {
		if _, err := regexp.Compile(p); err != nil {
			return nil, fmt.Errorf("%s: %w", arg, err)
		}
	}
	// With one marker, the section runs as far as it can, as in Ansible.
	body := "(?P<" + sectionGroup + ">.*?)"
	if r.After == "" || r.Before == "" {
		body = "(?P<" + sectionGroup + ">.*)"
	}
	return regexp.Compile("(?s)(?:" + r.After + ")" + body + "(?:" + r.Before + ")")
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
// checkRefs refuses a ${1} or ${name} in tmpl, the argument called arg,
// that names no group of re, and reports whether tmpl refers to none.
func checkRefs(re *regexp.Regexp, tmpl, arg string) (literal bool, err error) {
	names := map[string]bool{}
	for i, n := range re.SubexpNames() {
		names[strconv.Itoa(i)] = true
		if n != "" {
			names[n] = true
		}
	}
	literal = true
	for _, m := range templateRef.FindAllStringSubmatch(tmpl, -1) {
		if m[0] == "$$" {
			continue
		}
		literal = false
		if ref := m[1] + m[2]; !names[ref] {
			return false, fmt.Errorf("%s: %s isn't a group in regexp; to follow a group with letters or digits, write ${1}", arg, m[0])
		}
	}
	return literal, nil
}

func (r Replace) Validate() error {
	re, err := r.compile()
	if err != nil {
		return err
	}
	if _, err := r.sectionRegexp(); err != nil {
		return err
	}
	literal, err := checkRefs(re, r.With, "replace")
	if err != nil {
		return err
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
	section, err := r.sectionRegexp()
	if err != nil {
		return "", err
	}
	once := func(s string) string {
		if section == nil {
			return re.ReplaceAllString(s, r.With)
		}
		// Markers that don't match leave the file alone, as in Ansible.
		m := section.FindStringSubmatchIndex(s)
		if m == nil {
			return s
		}
		i := 2 * section.SubexpIndex(sectionGroup)
		return s[:m[i]] + re.ReplaceAllString(s[m[i]:m[i+1]], r.With) + s[m[i+1]:]
	}
	edited := once(content)
	if once(edited) != edited {
		return "", r.neverSettles()
	}
	return edited, nil
}
