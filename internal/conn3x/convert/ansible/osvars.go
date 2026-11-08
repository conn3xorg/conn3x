// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
	"gopkg.in/yaml.v3"
)

// Cross-distribution roles load their settings by OS family:
//
//	- include_vars: "{{ ansible_facts.os_family }}.yml"
//
// Conn3x reads each host's family with the conn3x_host data source, so a
// task that reads one of those variables is converted once for each family
// Conn3x supports, with that family's values, and becomes one step whose
// values differ by family:
//
//	name = { debian = "apache2", redhat = "httpd" }[local.os_family[each.key]]
//
// Each family's values go through the module's checks as written values do,
// so a path is proved to be a path on both.

// osFamilies are the families conn3x_host reports, by Ansible's name.
var osFamilies = []struct{ ansible, conn3x string }{{"Debian", "debian"}, {"RedHat", "redhat"}}

// osFamilyInclude matches include_vars of the host's family's file.
var osFamilyInclude = regexp.MustCompile(`^\{\{\s*ansible_(?:facts\.os_family|facts\[["']os_family["']\]|os_family)\s*\}\}\.(ya?ml)$`)

// familyVars finds a role's include_vars of vars/<family>.yml among its
// tasks and reads Debian's and Red Hat's files. It returns the task, the
// values by family and name, and for a value it can't use, such as a list,
// why; or a nil task when there's no such include or a file is missing, and
// the include then goes to review as before.
func (c *converter) familyVars(tasks []*yaml.Node) (*yaml.Node, map[string]map[string]string, map[string]map[string]string) {
	for _, n := range tasks {
		t := mapping(n)
		arg, ok := t["include_vars"]
		if !ok {
			arg, ok = t["ansible.builtin.include_vars"]
		}
		extra := len(t) - 1
		if t["name"] != nil {
			extra--
		}
		if !ok || extra != 0 {
			continue
		}
		if arg.Kind == yaml.MappingNode && len(arg.Content) == 2 && arg.Content[0].Value == "file" {
			arg = arg.Content[1]
		}
		m := osFamilyInclude.FindStringSubmatch(scalar(arg))
		if arg.Kind != yaml.ScalarNode || m == nil {
			continue
		}
		vals, whys := map[string]map[string]string{}, map[string]map[string]string{}
		for _, f := range osFamilies {
			src, err := os.ReadFile(c.path("vars/" + f.ansible + "." + m[1]))
			var doc yaml.Node
			if err != nil || yaml.Unmarshal(src, &doc) != nil || len(doc.Content) == 0 {
				return nil, nil, nil
			}
			vals[f.conn3x], whys[f.conn3x] = map[string]string{}, map[string]string{}
			for _, kv := range pairs(doc.Content[0]) {
				if v, _, why := plainValue(kv[1]); why == "" {
					vals[f.conn3x][kv[0].Value] = v
				} else {
					whys[f.conn3x][kv[0].Value] = why
				}
			}
		}
		return n, vals, whys
	}
	return nil, nil, nil
}

// familyNames lists the per-family variables a task's arguments mention.
func (c *converter) familyNames(args map[string]*yaml.Node, vars map[string]string) []string {
	if c.role == nil || c.role.familyVars == nil {
		return nil
	}
	seen := map[string]bool{}
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n == nil {
			return
		}
		if n.Kind == yaml.ScalarNode {
			for _, m := range jinja.FindAllStringSubmatch(n.Value, -1) {
				name := m[1]
				if _, set := vars[name]; set || c.role.defaults[name] != nil {
					continue
				}
				for _, f := range osFamilies {
					_, ok := c.role.familyVars[f.conn3x][name]
					_, unusable := c.role.familyWhy[f.conn3x][name]
					if ok || unusable {
						seen[name] = true
					}
				}
			}
		}
		for _, k := range n.Content {
			walk(k)
		}
	}
	for _, v := range args {
		walk(v)
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// mergeFamilies joins one task's steps converted for each family into steps
// whose differing string values are looked up by the host's family. It
// returns a reason when they differ in anything else.
func mergeFamilies(byFamily map[string][]step) ([]step, string) {
	first := byFamily[osFamilies[0].conn3x]
	differs := "converts to different steps on Debian and Red Hat hosts, which the converter can't write as one step yet"
	for _, f := range osFamilies[1:] {
		if len(byFamily[f.conn3x]) != len(first) {
			return nil, differs
		}
	}
	out := make([]step, len(first))
	for i, s := range first {
		out[i] = s
		out[i].attrs = append([]attr(nil), s.attrs...)
		for _, f := range osFamilies[1:] {
			o := byFamily[f.conn3x][i]
			// suffix only tells several steps of one task apart.
			if o.module != s.module || (o.suffix != s.suffix && len(first) > 1) || len(o.attrs) != len(s.attrs) ||
				fmt.Sprint(o.notes) != fmt.Sprint(s.notes) || fmt.Sprintf("%#v", o.blocks) != fmt.Sprintf("%#v", s.blocks) {
				return nil, differs
			}
		}
		for j, a := range s.attrs {
			vals := map[string]cty.Value{}
			same := true
			for _, f := range osFamilies {
				o := byFamily[f.conn3x][i].attrs[j]
				if o.key != a.key || o.raw != a.raw {
					return nil, differs
				}
				vals[f.conn3x] = o.val
				same = same && o.val.RawEquals(a.val)
			}
			if same {
				continue
			}
			if a.raw != "" || a.val.Type() != cty.String {
				return nil, differs
			}
			var parts []string
			for _, f := range osFamilies {
				parts = append(parts, f.conn3x+" = "+string(hclwrite.TokensForValue(vals[f.conn3x]).Bytes()))
			}
			out[i].attrs[j] = attr{key: a.key, raw: "{ " + strings.Join(parts, ", ") + " }[local.os_family[each.key]]"}
		}
	}
	return out, ""
}

// familyHostsValidation checks os in host objects, as the official
// circuits do, for a circuit that reads it.
const familyHostsValidation = `
  validation {
    condition     = alltrue([for h in var.hosts : contains(["debian", "ubuntu", "rocky", "almalinux", "rhel", "fedora"], try(h.os, "debian"))])
    error_message = "A host object's os must be one of debian, ubuntu, rocky, almalinux, rhel or fedora. CentOS Linux reached end of life on 30 June 2024: use Rocky Linux."
  }
}
`

// familyBlocks are what a circuit using per-family values needs: each
// host's facts, and its family, from os in its host object when the caller
// gives one, as for a host that doesn't exist yet.
const familyBlocks = `
# Each host's OS family, for the values the role loads per family. A host
# object's os, such as "ubuntu", is used when given, as for a host this
# plan creates; otherwise its facts are read.
data "conn3x_host" "facts" {
  for_each = var.hosts

  ssh {
    host             = try(each.value.address, each.value)
    port             = try(each.value.port, var.ssh_port)
    user             = try(each.value.user, var.ssh_user)
    host_key         = try(each.value.host_key, null)
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  lifecycle {
    postcondition {
      condition     = try(local.os_families[each.value.os], self.os_family) == self.os_family
      error_message = "Host ${each.key} is ${self.os_family} family, not what its os says."
    }
  }
}

locals {
  os_families = {
    debian = "debian", ubuntu = "debian",
    rhel = "redhat", rocky = "redhat", almalinux = "redhat", fedora = "redhat",
  }
  os_family = { for name, h in var.hosts : name => try(local.os_families[h.os], data.conn3x_host.facts[name].os_family) }
}
`
