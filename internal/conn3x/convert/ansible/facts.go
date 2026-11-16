// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"gopkg.in/yaml.v3"
)

// Roles often name a value once and use it in several tasks:
//
//	- set_fact:
//	    certbot_script: "{{ certbot_dir }}/certbot-auto"
//
// When the value is text with only role defaults in braces, and the role
// sets the name nowhere else, it's the same as writing that text wherever
// the name is used. So the converter does just that: render expands it in
// place, and the default inside it is held to the same rules as if the task
// had named it, paths and validations included.

// plainFactValue is text with only {{ name }} references in braces.
var plainFactValue = regexp.MustCompile(`^(?:[^{}]|\{\{\s*[A-Za-z_][A-Za-z0-9_]*\s*\}\})*$`)

// plainFacts finds the set_fact values the converter can expand where
// they're used: by name, the value's text.
func (c *converter) plainFacts() map[string]string {
	r := c.role
	candidates, count := map[string]string{}, map[string]int{}
	registered := map[string]bool{}
	files, _ := filepath.Glob(c.path("tasks/*"))
	sort.Strings(files)
	for _, f := range files {
		if ext := filepath.Ext(f); ext != ".yml" && ext != ".yaml" {
			continue
		}
		src, err := os.ReadFile(f)
		var doc yaml.Node
		if err != nil || parse(src, &doc) != nil || len(doc.Content) == 0 {
			continue
		}
		var walk func(n *yaml.Node)
		walk = func(n *yaml.Node) {
			for _, t := range seq(n) {
				m := mapping(t)
				if reg := scalar(m["register"]); reg != "" {
					registered[reg] = true
				}
				for _, k := range []string{"block", "rescue", "always"} {
					walk(m[k])
				}
				sf := firstNode(m["set_fact"], m["ansible.builtin.set_fact"])
				if sf == nil {
					continue
				}
				plain := sf.Kind == yaml.MappingNode
				for k := range m {
					if k != "name" && k != "tags" && k != "set_fact" && k != "ansible.builtin.set_fact" {
						plain = false // a when, a loop: the value isn't the same everywhere
					}
				}
				for _, kv := range pairs(sf) {
					x := kv[0].Value
					count[x]++
					// A bare yes or true is a bool, which Ansible prints as True.
					if _, isBool := yamlBool(kv[1]); plain && kv[1].Kind == yaml.ScalarNode && !isBool {
						candidates[x] = kv[1].Value
					}
				}
			}
		}
		walk(doc.Content[0])
	}
	facts := map[string]string{}
	for x, v := range candidates {
		if count[x] != 1 || registered[x] || reserved[x] || !identifier.MatchString(x) || r.defaults[x] != nil || len(r.varFiles[x]) > 0 || !plainFactValue.MatchString(v) {
			continue
		}
		if _, isDefault := r.defaultOf[x]; isDefault {
			continue
		}
		facts[x] = v
	}
	// Every name in a value must be a role default that prints as Ansible
	// prints it, or another fact kept here. Drop the rest until it settles.
	for changed := true; changed; {
		changed = false
		for x, v := range facts {
			for _, m := range jinja.FindAllStringSubmatch(v, -1) {
				d := r.defaults[m[1]]
				_, isFact := facts[m[1]]
				if (d == nil || d.boolean) && !isFact || m[1] == x {
					delete(facts, x)
					changed = true
					break
				}
			}
		}
	}
	return facts
}

// expandFacts writes each plain fact's text in place of its name, so render
// sees only role defaults and literal text.
func (r *role) expandFacts(s string) string {
	if r == nil || len(r.facts) == 0 {
		return s
	}
	for i := 0; i < 8 && jinja.MatchString(s); i++ {
		next := jinja.ReplaceAllStringFunc(s, func(m string) string {
			if v, ok := r.facts[jinja.FindStringSubmatch(m)[1]]; ok {
				return v
			}
			return m
		})
		if next == s {
			break
		}
		s = next
	}
	return s
}

// factTask reports whether node only sets plain facts, which render expands
// where they're used, and the names it sets.
func (r *role) factTask(node *yaml.Node) ([]string, bool) {
	if r == nil || len(r.facts) == 0 {
		return nil, false
	}
	m := mapping(node)
	sf := firstNode(m["set_fact"], m["ansible.builtin.set_fact"])
	if sf == nil || sf.Kind != yaml.MappingNode {
		return nil, false
	}
	for k := range m {
		if k != "name" && k != "tags" && k != "set_fact" && k != "ansible.builtin.set_fact" {
			return nil, false
		}
	}
	var names []string
	for _, kv := range pairs(sf) {
		if v, ok := r.facts[kv[0].Value]; !ok || v != kv[1].Value {
			return nil, false
		}
		names = append(names, kv[0].Value)
	}
	return names, len(names) > 0
}
