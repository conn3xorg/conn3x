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
	"strconv"
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
	// sub is a term such as webservers[0:2], which Resolve turns into
	// picked when webservers is a group; until then it's a glob.
	sub    *subscript
	picked map[string]bool
}

// subscript is Ansible's group[n], group[from:to], group[from:] or
// group[:to], counted from 0 with to excluded, and negative from the end.
type subscript struct {
	group                 string
	from, to              int
	hasFrom, hasTo, colon bool
}

var subscriptTerm = regexp.MustCompile(`^([^\[\]*?]+)\[(-?[0-9]+)?(:)?(-?[0-9]+)?\]$`)

func parseSubscript(s string) *subscript {
	m := subscriptTerm.FindStringSubmatch(s)
	if m == nil || (m[2] == "" && m[3] == "") {
		return nil
	}
	sub := &subscript{group: m[1], colon: m[3] != ""}
	if m[2] != "" {
		sub.from, sub.hasFrom = atoi(m[2]), true
	}
	if m[4] != "" {
		sub.to, sub.hasTo = atoi(m[4]), true
	}
	if !sub.colon && m[4] != "" {
		return nil
	}
	return sub
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// pick is the hosts the subscript names from a group's hosts, in order.
func (s *subscript) pick(hosts []string) map[string]bool {
	n := len(hosts)
	at := func(i int) int {
		if i < 0 {
			i += n
		}
		return min(max(i, 0), n)
	}
	picked := map[string]bool{}
	if !s.colon {
		if i := s.from; (i >= 0 && i < n) || (i < 0 && -i <= n) {
			picked[hosts[at(i)]] = true
		}
		return picked
	}
	from, to := 0, n
	if s.hasFrom {
		from = at(s.from)
	}
	if s.hasTo {
		to = at(s.to)
	}
	for _, h := range hosts[from:max(from, to)] {
		picked[h] = true
	}
	return picked
}

// Parse reads a pattern. Terms are separated by "," or ":". A term is a
// host name, a glob with * ? and [ ], "all" for every host, or a regular
// expression after "~". A group with a subscript, such as webservers[0]
// or webservers[1:3], picks hosts by position once Resolve knows the
// group's order.
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
			t.glob, t.sub = s, parseSubscript(s)
			// A subscript such as [-1] needn't be a valid glob as well.
			if _, err := path.Match(s, ""); err != nil && t.sub == nil {
				return nil, fmt.Errorf("%q: %s isn't a valid glob", raw, s)
			}
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

// Resolve turns each subscript term whose group order knows into the hosts
// it picks: order gives a group's hosts in inventory order, or nil when
// there's no such group, and then the term stays a glob, so web[0] still
// matches a host named web0.
func (p *Pattern) Resolve(order func(group string) []string) {
	for _, list := range [][]term{p.any, p.every, p.none} {
		for i, t := range list {
			if t.sub == nil {
				continue
			}
			if hosts := order(t.sub.group); hosts != nil {
				list[i].picked = t.sub.pick(hosts)
			}
		}
	}
}

func (t term) matchName(name string) bool {
	if t.re != nil {
		return t.re.MatchString(name)
	}
	ok, _ := path.Match(t.glob, name)
	return ok
}

// match is whether the term names the host or one of its groups.
func (t term) match(host string, groups []string) bool {
	if t.picked != nil {
		return t.picked[host]
	}
	if t.matchName(host) {
		return true
	}
	for _, g := range groups {
		if t.matchName(g) {
			return true
		}
	}
	return false
}

// Match reports whether host matches the pattern.
func (p *Pattern) Match(host string) bool { return p.MatchIn(host, nil) }

// MatchIn reports whether host, in groups, matches the pattern: as in
// Ansible, a term matches a host by its name or the name of a group it's
// in, so "webservers:&eu" is the hosts in both groups.
func (p *Pattern) MatchIn(host string, groups []string) bool {
	ok := false
	for _, t := range p.any {
		if t.match(host, groups) {
			ok = true
			break
		}
	}
	for _, t := range p.every {
		ok = ok && t.match(host, groups)
	}
	for _, t := range p.none {
		ok = ok && !t.match(host, groups)
	}
	if ok {
		p.matched.Store(true)
	}
	return ok
}

// Matched reports whether any host has matched so far.
func (p *Pattern) Matched() bool { return p.matched.Load() }

func (p *Pattern) String() string { return p.raw }
