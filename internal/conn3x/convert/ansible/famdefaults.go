// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"gopkg.in/yaml.v3"
)

// Roles that load vars/<family>.yml usually let the caller override each
// setting, with the family's value as the default:
//
//	- set_fact:
//	    nginx_user: "{{ __nginx_user }}"
//	  when: nginx_user is not defined
//
// That becomes a variable the caller can set, null by default, and each use
// of it a choice between the two:
//
//	owner = var.nginx_user != null ? var.nginx_user : { debian = "www-data", redhat = "nginx" }[local.os_family[each.key]]
//
// A caller's value isn't known when converting, so, as with a role default,
// it's kept only where Conn3x uses it exactly as Ansible does.

var bareRef = regexp.MustCompile(`^\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}$`)

// familyDefaults finds the set_fact tasks that default a variable to a
// per-family one. It returns them by task, and the per-family name each
// variable defaults to.
func (c *converter) familyDefaults(tasks []taskAt, vars map[string]string) (map[string]string, map[string]string, map[string]map[string]bool) {
	nodes, alias, missing := map[string]string{}, map[string]string{}, map[string]map[string]bool{}
	r := c.role
	if r == nil || r.familyVars == nil {
		return nodes, alias, missing
	}
	for _, ta := range tasks {
		n := ta.node
		t := mapping(n)
		want := 2
		if t["name"] != nil {
			want = 3
		}
		sf, when := t["set_fact"], t["when"]
		if sf == nil {
			sf = t["ansible.builtin.set_fact"]
		}
		if len(t) != want || sf == nil || when == nil {
			continue
		}
		kv := pairs(sf)
		if len(kv) != 1 || kv[0][1].Kind != yaml.ScalarNode {
			continue
		}
		x := kv[0][0].Value
		m := bareRef.FindStringSubmatch(kv[0][1].Value)
		if m == nil || !identifier.MatchString(x) || reserved[x] || r.defaults[x] != nil || has(vars, x) {
			continue
		}
		cond := scalar(when)
		if when.Kind == yaml.SequenceNode && len(when.Content) == 1 {
			cond = scalar(when.Content[0])
		}
		if strings.Join(strings.Fields(cond), " ") != x+" is not defined" {
			continue
		}
		// An entry whose file doesn't set it is a host Ansible stops on
		// unless the caller sets x, as the steps' precondition says. One
		// that sets it must exist, or there's nothing to default to.
		gaps, some := map[string]bool{}, false
		for _, f := range c.axisFor(osFamilies) {
			if _, ok := r.familyVars[f.id()][m[1]]; ok {
				some = true
			} else {
				gaps[f.id()] = true
			}
		}
		if !some {
			continue
		}
		nodes[taskKey(ta.file, n)], alias[x] = x, m[1]
		if len(gaps) > 0 {
			missing[x] = gaps
		}
	}
	return nodes, alias, missing
}

// callerKeys checks that a task uses a caller-set variable only where its
// value goes through unchanged, and returns the reason if not.
func callerKeys(mod string, args map[string]*yaml.Node, names []string, alias map[string]string) string {
	for k, v := range args {
		for _, n := range names {
			if _, isDefault := alias[n]; !isDefault || !mentions(v, n) {
				continue
			}
			ok := false
			for _, vk := range verbatim[mod] {
				ok = ok || vk == k
			}
			if !ok {
				return fmt.Sprintf("%s refers to %q, which the caller can set, and the converter keeps a caller's value only where Conn3x uses it exactly as Ansible does; here it would have to check the value first", k, n)
			}
		}
	}
	return ""
}

func mentions(n *yaml.Node, name string) bool {
	if n == nil {
		return false
	}
	if n.Kind == yaml.ScalarNode {
		for _, m := range jinja.FindAllStringSubmatch(n.Value, -1) {
			if m[1] == name {
				return true
			}
		}
	}
	for _, k := range n.Content {
		if mentions(k, name) {
			return true
		}
	}
	return false
}

// withCaller wraps each attribute that carries a caller-set variable in the
// caller run: the caller's value when set, else the family's.
func withCaller(merged []step, callerByFamily map[string][]step, alias map[string]string, fams []osFamily) ([]step, string) {
	first := callerByFamily[fams[0].id()]
	if len(first) != len(merged) {
		return nil, "converts to different steps when the caller sets a value, which the converter can't write as one step yet"
	}
	for i := range merged {
		for _, f := range fams[1:] {
			if len(callerByFamily[f.id()]) != len(first) || len(callerByFamily[f.id()][i].attrs) != len(first[i].attrs) {
				return nil, "converts to different steps when the caller sets a value, which the converter can't write as one step yet"
			}
		}
		if len(first[i].attrs) != len(merged[i].attrs) {
			return nil, "converts to different steps when the caller sets a value, which the converter can't write as one step yet"
		}
		for j, a := range first[i].attrs {
			var used []string
			for x := range alias {
				if regexp.MustCompile(`\bvar\.` + regexp.QuoteMeta(x) + `\b`).MatchString(a.raw) {
					used = append(used, x)
				}
			}
			if len(used) == 0 {
				continue
			}
			if len(used) > 1 {
				return nil, a.key + " combines several values the caller can set, which the converter can't write yet"
			}
			for _, f := range fams[1:] {
				if o := callerByFamily[f.id()][i].attrs[j]; o.raw != a.raw {
					return nil, a.key + " mixes a value the caller can set with ones that differ by family, which the converter can't write yet"
				}
			}
			fam := merged[i].attrs[j]
			famExpr := fam.raw
			if famExpr == "" {
				famExpr = strings.TrimSpace(string(hclwrite.TokensForValue(fam.val).Bytes()))
			}
			merged[i].attrs[j] = attr{key: a.key, raw: fmt.Sprintf("var.%s != null ? %s : %s", used[0], a.raw, famExpr)}
		}
	}
	return merged, ""
}
