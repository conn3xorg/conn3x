// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// A no_log task in a role converts when every value it passes is a role
// variable that reaches the host only through a write-only argument: state
// never keeps those, the variable is sensitive, so plans hide it, and it's
// ephemeral too when nothing else reads it. Anything else stays for review.

// writeOnlyFor is, by step module, the write-only argument that takes each
// argument's value. A template's vars go to content_wo through write_only.
var writeOnlyFor = map[string]map[string]string{
	"file":     {"content": "content_wo"},
	"template": {"vars": "write_only"},
}

// passwordFor is, by step module, the write-only argument an Ansible
// argument the module never copies goes to, and that argument: the
// password, or debconf's value. user's password is a crypt hash.
var passwordFor = map[string][2]string{
	"mysql_user":      {"password", "password_wo"},
	"postgresql_role": {"password", "password_wo"},
	"htpasswd":        {"password", "password_wo"},
	"user":            {"password", "password_hash_wo"},
	"debconf":         {"value", "value_wo"},
}

// stepRef finds what an argument's expression reads; path.module is the
// circuit's own directory, so it isn't one.
var stepRef = regexp.MustCompile(`\b(var|local|each|data|step|module|self|count)\.([A-Za-z_][A-Za-z0-9_]*)`)

// noLogFirst is why a no_log task stays before its steps are built: only a
// role's task, with no_log on itself and no loop or block, can convert.
func (c *converter) noLogFirst(node *yaml.Node, t map[string]*yaml.Node) string {
	if c.role == nil || noLogOf(node) == nil || t["block"] != nil {
		return noLogReason
	}
	for k := range t {
		if k == "loop" || strings.HasPrefix(k, "with_") {
			return noLogReason
		}
	}
	return ""
}

// protectSecrets moves each value a no_log task's steps take into the
// step's write-only argument, or says why it can't: a value with no
// write-only form, one written into the role, or one that isn't a role
// variable. It counts each variable's uses for the ephemeral check.
func (c *converter) protectSecrets(steps []step, args map[string]*yaml.Node, when *yaml.Node) string {
	total := map[string]int{}
	var uses map[string]int // the current step's
	// check reads a write-only value: every reference a role variable.
	check := func(key, expr string) string {
		refs := stepRef.FindAllStringSubmatch(expr, -1)
		if len(refs) == 0 {
			return fmt.Sprintf("sets no_log and gives %s a value written into the role, so the secret would be in this file too; pass it in a role default instead", key)
		}
		for _, m := range refs {
			if m[1] != "var" || !c.role.carried[m[2]] {
				return fmt.Sprintf("sets no_log and gives %s %s, which isn't a role default the converter carries over, so it can't keep the value out of this file", key, m[0])
			}
			uses[m[2]]++
			total[m[2]]++
		}
		return ""
	}
	for i := range steps {
		s := &steps[i]
		if s.module == "" {
			continue
		}
		uses = map[string]int{}
		for _, b := range s.blocks {
			for _, a := range b.attrs {
				if strings.Contains(a.val.GoString(), "\x00") {
					return fmt.Sprintf("sets no_log and passes a value to %s.%s, which has no write-only form, so it would be in plans and state", b.name, a.key)
				}
			}
		}
		for j := range s.attrs {
			a := &s.attrs[j]
			wo, mapped := writeOnlyFor[s.module][a.key]
			if !mapped && !strings.HasSuffix(a.key, "_wo") {
				if refs := stepRef.FindAllString(a.raw, -1); len(refs) > 0 {
					return fmt.Sprintf("sets no_log and passes %s to the %s step's %s, which has no write-only form, so its value would be in plans and state", refs[0], s.module, a.key)
				}
				continue
			}
			expr := a.raw
			if expr == "" {
				expr = a.val.GoString() // a literal: check refuses it
			}
			if why := check(a.key, expr); why != "" {
				return why
			}
			switch {
			case wo == "write_only":
				s.attrs = append(s.attrs, attr{key: "write_only", raw: "true"})
			case mapped:
				a.key = wo
			}
		}
		pw, ok := passwordFor[s.module]
		if s.module == "debconf" && scalar(args["vtype"]) != "password" {
			ok = false // the step copies any other answer as value
		}
		if n := args[pw[0]]; ok && n != nil {
			v := scalar(n)
			if m := bareRef.FindStringSubmatch(v); m != nil {
				v = "var." + m[1]
			} else if strings.Contains(v, "{{") {
				// Not echoed: an expression can hold the secret, as in default('x').
				return fmt.Sprintf("sets no_log and gives %s an expression rather than one role default, so the converter can't keep the value out of this file", pw[0])
			}
			if why := check(pw[0], v); why != "" {
				return why
			}
			s.attrs = append(s.attrs, attr{key: pw[1], raw: v})
			// The step now sets it, so the note asking for it goes.
			s.notes = slices.DeleteFunc(s.notes, func(n string) bool { return strings.HasPrefix(n, "TODO(convert): Set "+pw[1]+" ") })
			if s.module == "user" && scalar(args["update_password"]) == "on_create" {
				s.attrs = append(s.attrs, attr{key: "password_on_create", raw: "true"})
			}
		}
		if len(uses) > 0 {
			s.notes = append(s.notes, noLogNote(uses))
		}
	}
	if len(total) == 0 {
		return noLogReason
	}
	// A when that reads a secret runs at plan time and lowers to for_each,
	// which refuses a sensitive value, and the value couldn't stay out of
	// the plan anyway.
	if when != nil {
		text, _ := yaml.Marshal(when)
		names := make([]string, 0, len(total))
		for n := range total {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if regexp.MustCompile(`\b` + regexp.QuoteMeta(n) + `\b`).Match(text) {
				return fmt.Sprintf("sets no_log and tests var.%s in when, which runs at plan time, so the value can't stay out of the plan", n)
			}
		}
	}
	for n, k := range total {
		c.role.secrets[n] += k
	}
	return ""
}

// noLogNote says how a converted no_log task's secrets reach the host.
func noLogNote(uses map[string]int) string {
	names := make([]string, 0, len(uses))
	for n := range uses {
		names = append(names, "var."+n)
	}
	sort.Strings(names)
	if len(names) == 1 {
		return "From a no_log task: " + names[0] + " reaches the host only through a write-only argument, which state never keeps, and the variable is sensitive, so plans hide it."
	}
	return "From a no_log task: " + joinAnd(names) + " reach the host only through write-only arguments, which state never keeps, and the variables are sensitive, so plans hide them."
}

// ephemeralOK reports whether a sensitive variable can also be ephemeral:
// every use of it in the circuit, comments aside, is a write-only argument.
func (r *role) ephemeralOK(name string, circuit []byte) bool {
	ref := regexp.MustCompile(`\bvar\.` + regexp.QuoteMeta(name) + `\b`)
	n := 0
	for _, line := range strings.Split(string(circuit), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			n += len(ref.FindAllString(line, -1))
		}
	}
	return n > 0 && n == r.secrets[name]
}
