// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package hostpattern reads Ansible-style host patterns, such as
// "web*,db1", "web*:!web3" or "~^db[0-9]$", and matches host names
// against them.
package hostpattern

import (
	"fmt"
	"path"
	"regexp"
	"strings"
	"sync/atomic"
)

// Pattern is a parsed host pattern. As in Ansible, a host matches when it
// matches any plain term, every "&" term, and no "!" term.
type Pattern struct {
	raw              string
	any, every, none []term
	matched          atomic.Bool
}

type term struct {
	glob string
	re   *regexp.Regexp
}

// Parse reads a pattern. Terms are separated by "," or ":". A term is a
// host name, a glob with * ? and [ ], "all" for every host, or a regular
// expression after "~".
// "&" in front of a term narrows to the hosts it matches too, and "!"
// leaves out the hosts it matches.
func Parse(raw string) (*Pattern, error) {
	p := &Pattern{raw: raw}
	for _, s := range split(raw) {
		s = strings.TrimSpace(s)
		list := &p.any
		switch {
		case strings.HasPrefix(s, "&"):
			list, s = &p.every, s[1:]
		case strings.HasPrefix(s, "!"):
			list, s = &p.none, s[1:]
		}
		if s == "" {
			return nil, fmt.Errorf("%q has an empty term", raw)
		}
		var t term
		if strings.HasPrefix(s, "~") {
			re, err := regexp.Compile(s[1:])
			if err != nil {
				return nil, fmt.Errorf("%q: %s isn't a regular expression: %w", raw, s, err)
			}
			t.re = re
		} else {
			if s == "all" {
				s = "*" // as in Ansible
			}
			if _, err := path.Match(s, ""); err != nil {
				return nil, fmt.Errorf("%q: %s isn't a valid glob", raw, s)
			}
			t.glob = s
		}
		*list = append(*list, t)
	}
	if len(p.any) == 0 {
		if len(p.every) == 0 && len(p.none) == 0 {
			return nil, fmt.Errorf("%q names no hosts", raw)
		}
		p.any = []term{{glob: "*"}} // "!web3" alone means every host but web3
	}
	return p, nil
}

// split cuts raw at each "," or ":" outside brackets, so a regular
// expression such as ~^web{1,2}$ stays one term.
func split(raw string) []string {
	var out []string
	depth, start := 0, 0
	for i, r := range raw {
		switch r {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth = max(depth-1, 0)
		case ',', ':':
			if depth == 0 {
				if i > start {
					out = append(out, raw[start:i])
				}
				start = i + 1
			}
		}
	}
	if start < len(raw) {
		out = append(out, raw[start:])
	}
	return out
}

func (t term) match(host string) bool {
	if t.re != nil {
		return t.re.MatchString(host)
	}
	ok, _ := path.Match(t.glob, host)
	return ok
}

// Match reports whether host matches the pattern.
func (p *Pattern) Match(host string) bool {
	ok := false
	for _, t := range p.any {
		if t.match(host) {
			ok = true
			break
		}
	}
	for _, t := range p.every {
		ok = ok && t.match(host)
	}
	for _, t := range p.none {
		ok = ok && !t.match(host)
	}
	if ok {
		p.matched.Store(true)
	}
	return ok
}

// Matched reports whether any host has matched so far.
func (p *Pattern) Matched() bool { return p.matched.Load() }

func (p *Pattern) String() string { return p.raw }
