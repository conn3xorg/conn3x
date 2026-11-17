// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
	"gopkg.in/yaml.v3"
)

// A role becomes a circuit directory: its tasks the steps, its handlers the
// handlers, its defaults variables the caller can set, and its vars filled
// in where they're used, since in Ansible they beat everything a play sets.
// The files and templates its tasks use are copied in beside them.

type role struct {
	defaults  map[string]*roleDefault
	files     map[string][]byte   // files for the circuit directory besides the HCL
	commaFree map[string]bool     // defaults used as package names
	pathRules map[string][]string // what defaults used in paths must hold to; see input.pathRules
	// handlerState are defaults a handler's state follows, which must stay
	// restarted or reloaded.
	handlerState map[string]bool
	// varFiles are the files under vars/ other than main that set each
	// variable, such as vars/Debian.yml: what an include_vars loads.
	varFiles map[string][]string
	// familyVars are what the files varsIncludes load set, by axis entry;
	// familyUsed is set once a step looks one up. familyIncludeAt is where
	// each include is, file:line, for includes in an imported file, which is
	// read again for each pass.
	familyIncludeAt []string
	familyVars      map[string]map[string]string
	familyWhy       map[string]map[string]string // why a value can't be used, such as a list
	// axis is what familyVars are keyed by: the families, or, when
	// versioned, one entry for each list of vars files a host can load, and
	// varsIncludes the include_vars tasks that pick them (see
	// versionBlocks).
	axis         []osFamily
	versioned    bool
	varsIncludes []varsInclude
	familyUsed   bool
	// packagesUsed is set once a step's when tests an installed package.
	packagesUsed bool
	// defaultTasks are the set_fact tasks that default a variable to a
	// per-family one, and defaultOf maps each such variable to that one;
	// defaultUsed are those a step reads, which become variables.
	defaultTasks map[*yaml.Node]string
	// facts are the set_fact values render writes in place of their names;
	// see plainFacts.
	facts       map[string]string
	defaultOf   map[string]string
	defaultUsed map[string]bool
	// shadowed are defaults a file under vars/ also sets.
	shadowed map[string]bool
	// lists are the defaults that are lists of plain values, kept apart
	// so only a loop over one uses them; listUsed are those a loop reads,
	// which become variables.
	lists    map[string][]string
	listUsed map[string]bool
	// maps are the defaults that are lists of maps of plain values. An
	// empty list in lists can be read either way. mapFields are the fields
	// loops read from each, nil where a bare read makes one required and
	// the default otherwise; mapKeys are the fields that key a loop.
	maps      map[string][]map[string]string
	mapFields map[string]map[string]*string
	mapKeys   map[string][]string
	// probes are the register names of probes converted to data sources,
	// and probeBlocks those blocks, written after the circuit.
	probes      map[string]*probe
	probeBlocks []string
}

type roleDefault struct {
	value   string
	number  bool
	boolean bool // yes, no, true, false, on or off, as YAML 1.1 reads them
}

// defaultOrNil is the role default called name, or nil, also on a nil role.
func (r *role) defaultOrNil(name string) *roleDefault {
	if r == nil {
		return nil
	}
	return r.defaults[name]
}

// reserved are variable names the circuit already uses or HCL won't take.
var reserved = map[string]bool{
	"hosts": true, "ssh_user": true, "ssh_port": true, "ssh_private_key_file": true,
	"ssh_known_hosts_file": true, "ssh_become": true, "source": true, "version": true,
	"providers": true, "count": true, "for_each": true, "lifecycle": true, "depends_on": true, "locals": true,
}

// ConvertRole reads the Ansible role in dir and translates it into the files
// of a circuit directory.
func ConvertRole(dir string) (Result, error) { return convertRoleDir(dir, false, nil, "") }

// convertRoleDir is ConvertRole. depsCalled says the caller calls the role's
// meta/ dependencies itself, so they aren't left for review. entry names
// the files to start from instead of main, as include_role's tasks_from does.
// loopVar is the variable a looped call sets for each item, which the
// circuit then requires.
func convertRoleDir(dir string, depsCalled bool, entry map[string]string, loopVar string) (Result, error) {
	if st, err := os.Stat(filepath.Join(dir, "tasks")); err != nil || !st.IsDir() {
		return Result{}, fmt.Errorf("%s has no tasks/ directory, so it isn't a role; point -role at the role's own directory", dir)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return Result{}, err
	}
	base := filepath.Base(abs)
	// A Galaxy role installs as namespace.name.
	name := slug(base[strings.LastIndex(base, ".")+1:])
	r := &role{defaults: map[string]*roleDefault{}, files: map[string][]byte{}, commaFree: map[string]bool{}, shadowed: map[string]bool{}, lists: map[string][]string{}, listUsed: map[string]bool{}, maps: map[string][]map[string]string{}, mapFields: map[string]map[string]*string{}, mapKeys: map[string][]string{}, probes: map[string]*probe{}, pathRules: map[string][]string{}, handlerState: map[string]bool{}}
	c := &converter{dir: dir, role: r, depsCalled: depsCalled, entry: entry}
	r.varFiles = c.otherVarFiles()

	f := hclwrite.NewEmptyFile()
	body := f.Body()
	from := ""
	for _, sub := range []string{"tasks", "vars", "defaults", "handlers"} {
		if f, ok := entry[sub]; ok {
			from += ", " + entryFile(dir, sub, f)
		}
	}
	if from != "" {
		from = " (from " + from[2:] + ")"
	}
	comment(body, fmt.Sprintf("Converted from the Ansible role %s%s by conn3x convert ansible.", base, from))
	comment(body, "Search for TODO(convert) to find what still needs a person.")
	body.AppendNewline()
	c.meta(body)

	vars := map[string]string{}
	varsNode, varsFile := c.main(body, "vars")
	for _, kv := range pairs(varsNode) {
		if v, _, why := plainValue(kv[1]); why == "" {
			vars[kv[0].Value] = v
		}
	}

	vf := hclwrite.NewEmptyFile()
	vb := vf.Body()
	defaultsNode, defaultsFile := c.main(body, "defaults")
	var order, listOrder []string
	listWhere := map[string]string{}
	for _, kv := range pairs(defaultsNode) {
		k := kv[0].Value
		where := fmt.Sprintf("Default %q (%s line %d)", k, defaultsFile, kv[0].Line)
		if items, ok := plainList(kv[1]); ok && !has(vars, k) && len(r.varFiles[k]) == 0 && !reserved[k] && identifier.MatchString(k) {
			r.lists[k] = items
			listOrder = append(listOrder, k)
			listWhere[k] = where
			continue
		}
		if items, ok := mapList(kv[1]); ok && !has(vars, k) && len(r.varFiles[k]) == 0 && !reserved[k] && identifier.MatchString(k) {
			r.maps[k] = items
			listOrder = append(listOrder, k)
			listWhere[k] = where
			continue
		}
		v, number, why := plainValue(kv[1])
		boolean := false
		if b, ok := yamlBool(kv[1]); ok {
			v, boolean, why = strconv.FormatBool(b), true, ""
		}
		switch {
		case has(vars, k):
			why = "is also set in " + varsFile + ", which wins in Ansible, so it stays fixed"
		case len(r.varFiles[k]) > 0:
			// Role vars beat defaults, so once an include_vars loads one of
			// these, the default no longer counts.
			why = "is also set in " + joinAnd(r.varFiles[k]) + ", which wins in Ansible once an include_vars loads it, so tasks use the value from there"
			r.shadowed[k] = true
		case reserved[k] || !identifier.MatchString(k):
			why = "has a name the circuit can't use for a variable"
		case why != "":
			why = "is " + why + ", which the converter can't carry over as a variable yet"
		}
		if why != "" {
			vb.AppendNewline()
			comment(vb, where+" "+why+". Tasks that use it are marked TODO(convert).")
			continue
		}
		r.defaults[k] = &roleDefault{value: v, number: number, boolean: boolean}
		order = append(order, k)
	}
	// The loop's item beats the role's vars/ and defaults, as a task's
	// vars do in Ansible.
	if loopVar != "" {
		delete(vars, loopVar)
		order = slices.DeleteFunc(order, func(k string) bool { return k == loopVar })
		r.defaults[loopVar] = &roleDefault{}
	}

	tasks, tasksFile := c.main(body, "tasks")
	handlers, handlersFile := c.main(body, "handlers")
	if len(c.res.Review) > 0 {
		body.AppendNewline()
	}
	circuit := body.AppendNewBlock("circuit", []string{name})
	cb := circuit.Body()
	cb.SetAttributeRaw("hosts", rawTokens("var.hosts"))
	cb.AppendNewline()
	ssh := cb.AppendNewBlock("ssh", nil).Body()
	for _, a := range []string{"user", "port", "private_key_file", "known_hosts_file", "become"} {
		ssh.SetAttributeRaw(a, rawTokens("var.ssh_"+a))
	}
	c.file = tasksFile
	r.varsIncludes, r.axis, r.versioned, r.familyVars, r.familyWhy = c.familyVars(seq(tasks))
	if r.varsIncludes == nil {
		// The include may be in a file main.yml imports, such as
		// include-vars.yml.
		var nodes []*yaml.Node
		files := map[*yaml.Node]string{}
		for _, t := range c.flatten(seq(tasks), tasksFile, []string{tasksFile}) {
			nodes = append(nodes, t.node)
			files[t.node] = t.file
		}
		if r.varsIncludes, r.axis, r.versioned, r.familyVars, r.familyWhy = c.familyVars(nodes); r.varsIncludes != nil {
			for _, inc := range r.varsIncludes {
				r.familyIncludeAt = append(r.familyIncludeAt, fmt.Sprintf("%s:%d", files[inc.node], inc.node.Line))
			}
		}
	}
	r.defaultTasks, r.defaultOf = c.familyDefaults(seq(tasks), vars)
	r.facts = c.plainFacts()
	r.defaultUsed = map[string]bool{}
	c.steps(cb, at(seq(tasks), c.file), seq(handlers), handlersFile, false, vars)
	if r.familyUsed {
		body.AppendUnstructuredTokens(rawTokens(familyBlocks))
		if r.versioned {
			body.AppendUnstructuredTokens(rawTokens(c.versionBlocks(r.varsIncludes)))
		}
	}
	for _, b := range r.probeBlocks {
		body.AppendUnstructuredTokens(rawTokens(b))
	}
	if r.packagesUsed {
		body.AppendUnstructuredTokens(rawTokens(packagesBlocks))
	}

	for _, k := range order {
		d := r.defaults[k]
		b := hclwrite.NewBlock("variable", []string{k})
		switch {
		case d.boolean:
			b.Body().SetAttributeRaw("type", rawTokens("bool"))
			b.Body().SetAttributeRaw("default", rawTokens(d.value))
		case d.number:
			b.Body().SetAttributeRaw("type", rawTokens("number"))
			b.Body().SetAttributeRaw("default", rawTokens(d.value))
		default:
			b.Body().SetAttributeRaw("type", rawTokens("string"))
			b.Body().SetAttributeValue("default", cty.StringVal(d.value))
		}
		b.Body().SetAttributeValue("description", cty.StringVal("From the role's "+defaultsFile+"."))
		if r.commaFree[k] {
			v := b.Body().AppendNewBlock("validation", nil).Body()
			v.SetAttributeRaw("condition", rawTokens(fmt.Sprintf(`!strcontains(var.%s, ",")`, k)))
			v.SetAttributeValue("error_message", cty.StringVal(k+" names one package, so it can't have a comma; Ansible would read one as a list."))
		}
		if r.handlerState[k] {
			v := b.Body().AppendNewBlock("validation", nil).Body()
			v.SetAttributeRaw("condition", rawTokens(fmt.Sprintf(`contains(["restarted", "reloaded"], var.%s)`, k)))
			v.SetAttributeValue("error_message", cty.StringVal(k+" is a handler's state, so it must be restarted or reloaded, the two a Conn3x handler does."))
		}
		pathValidations(b.Body(), k, "", r.pathRules[k], false)
		vb.AppendNewline()
		vb.AppendBlock(b)
	}

	for _, k := range listOrder {
		vb.AppendNewline()
		if r.mapFields[k] != nil {
			r.mapVariable(vb, k, defaultsFile)
			continue
		}
		if !r.listUsed[k] {
			comment(vb, listWhere[k]+" is a list, which the converter carries over as a variable only for a loop over it. Tasks that use it are marked TODO(convert).")
			continue
		}
		vals := make([]cty.Value, len(r.lists[k]))
		for i, it := range r.lists[k] {
			vals[i] = cty.StringVal(it)
		}
		b := vb.AppendNewBlock("variable", []string{k}).Body()
		b.SetAttributeRaw("type", rawTokens("list(string)"))
		if len(vals) == 0 {
			b.SetAttributeRaw("default", rawTokens("[]"))
		} else {
			b.SetAttributeValue("default", cty.ListVal(vals))
		}
		b.SetAttributeValue("description", cty.StringVal("From the role's "+defaultsFile+". Each item is one pass of the loop that uses it, so the list can't hold the same value twice."))
		if r.commaFree[k] {
			v := b.AppendNewBlock("validation", nil).Body()
			v.SetAttributeRaw("condition", rawTokens(fmt.Sprintf(`alltrue([for p in var.%s : !strcontains(p, ",")])`, k)))
			v.SetAttributeValue("error_message", cty.StringVal("Each item of "+k+" names one package, so it can't have a comma; Ansible would read one as a list."))
		}
		pathValidations(b, k, "", r.pathRules[k], true)
	}

	var looped []string
	if loopVar != "" {
		b := hclwrite.NewBlock("variable", []string{loopVar})
		b.Body().SetAttributeRaw("type", rawTokens("string"))
		b.Body().SetAttributeValue("description", cty.StringVal("One item of the caller's loop, which the role reads as "+loopVar+"."))
		vb.AppendNewline()
		vb.AppendBlock(b)
		looped = []string{loopVar}
	}

	used := make([]string, 0, len(r.defaultUsed))
	for x := range r.defaultUsed {
		used = append(used, x)
	}
	sort.Strings(used)
	for _, x := range used {
		b := hclwrite.NewBlock("variable", []string{x})
		b.Body().SetAttributeRaw("type", rawTokens("string"))
		b.Body().SetAttributeRaw("default", rawTokens("null"))
		b.Body().SetAttributeValue("description", cty.StringVal(fmt.Sprintf("Set by the caller; otherwise %s from vars/<family>.yml, for each host's family.", r.defaultOf[x])))
		vb.AppendNewline()
		vb.AppendBlock(b)
	}

	files := r.files
	files["main.circuit.hcl"] = hclwrite.Format(f.Bytes())
	variables := circuitVariables
	if r.familyUsed {
		// The circuit reads os from host objects; check it as the official
		// circuits do.
		hostsEnd := "\n  }\n}\n"
		i := strings.Index(variables, hostsEnd)
		variables = variables[:i] + "\n  }\n" + familyHostsValidation + variables[i+len(hostsEnd):]
		variables = strings.Replace(variables, "settings such as host_key.", "settings such as host_key, and os (debian, ubuntu, rocky, almalinux, rhel or fedora) for a host whose facts can't be read yet.", 1)
	}
	files["variables.tf"] = append([]byte(variables), hclwrite.Format(vf.Bytes())...)
	files["outputs.tf"] = []byte("# An Ansible role has no outputs. Add any you want callers to read here.\n")
	files["README.md"] = readme(base, name, len(c.res.Review), order, r.defaults)
	if len(used) > 0 {
		var b strings.Builder
		axis := c.axisFor(osFamilies)
		if !r.versioned {
			b.WriteString("\nThese take each host's OS family's value from the role's `vars/` unless you set them:\n\n| Name | Debian and Ubuntu | Red Hat family |\n")
		} else {
			b.WriteString("\nThese take the value from the `vars/` file each host loads unless you set them:\n\n| Name |")
			for _, f := range axis {
				fmt.Fprintf(&b, " `%s` |", f.file)
			}
			b.WriteString("\n")
		}
		b.WriteString("| --- |" + strings.Repeat(" --- |", len(axis)) + "\n")
		for _, x := range used {
			y := r.defaultOf[x]
			fmt.Fprintf(&b, "| `%s` |", x)
			for _, f := range axis {
				fmt.Fprintf(&b, " `%s` |", r.familyVars[f.id()][y])
			}
			b.WriteString("\n")
		}
		files["README.md"] = append(files["README.md"], b.String()...)
	}
	c.res.Files = files
	c.res.Variables = slices.Concat(order, used, looped)
	return c.res, nil
}

var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// otherVarFiles reads the top-level names set in vars/*.yml besides main,
// so a reason can say a variable comes from one of them. A file that can't
// be read is left out; it only makes the reason less specific.
func (c *converter) otherVarFiles() map[string][]string {
	out := map[string][]string{}
	matches, _ := filepath.Glob(c.path("vars/*"))
	sort.Strings(matches)
	for _, m := range matches {
		base := filepath.Base(m)
		ext := filepath.Ext(base)
		if (ext != ".yml" && ext != ".yaml") || strings.TrimSuffix(base, ext) == "main" {
			continue
		}
		src, err := os.ReadFile(m)
		var doc yaml.Node
		if err != nil || parse(src, &doc) != nil || len(doc.Content) == 0 {
			continue
		}
		for _, kv := range pairs(doc.Content[0]) {
			out[kv[0].Value] = append(out[kv[0].Value], "vars/"+base)
		}
	}
	return out
}

// entryFile is the file under the role in dir that sub/f names, as Ansible
// finds it: f itself when it has an extension, and otherwise f.yml, f.yaml
// or f. It's empty when there's none.
func entryFile(dir, sub, f string) string {
	names := []string{f}
	if ext := filepath.Ext(f); ext != ".yml" && ext != ".yaml" {
		names = []string{f + ".yml", f + ".yaml", f}
	}
	for _, n := range names {
		rel := filepath.ToSlash(filepath.Join(sub, n))
		if st, err := os.Stat(filepath.Join(dir, rel)); err == nil && !st.IsDir() {
			return rel
		}
	}
	return ""
}

// main reads a role's sub/main.yml, or .yaml, or main, as Ansible does,
// returning the document and the file it read. With an entry for sub, it
// reads that file instead.
func (c *converter) main(body *hclwrite.Body, sub string) (*yaml.Node, string) {
	names := []string{"main.yml", "main.yaml", "main"}
	if f, ok := c.entry[sub]; ok {
		names = []string{strings.TrimPrefix(entryFile(c.dir, sub, f), sub+"/")}
	}
	for _, n := range names {
		rel := filepath.ToSlash(filepath.Join(sub, n))
		st, err := os.Stat(c.path(rel))
		if err != nil {
			continue
		}
		if st.IsDir() {
			c.note(body, sub, rel, 0, "keeps its "+sub+" in a directory of files, which the converter can't read yet")
			return nil, rel
		}
		src, err := os.ReadFile(c.path(rel))
		var doc yaml.Node
		if err == nil {
			err = parse(src, &doc)
		}
		if err != nil {
			c.note(body, sub, rel, 0, "can't be read: "+err.Error())
			return nil, rel
		}
		if len(doc.Content) == 0 {
			return nil, rel
		}
		return doc.Content[0], rel
	}
	return nil, filepath.ToSlash(filepath.Join(sub, "main.yml"))
}

// meta notes what meta/ asks of Ansible that the circuit doesn't do.
func (c *converter) meta(body *hclwrite.Body) {
	m, file := c.main(body, "meta")
	t := mapping(m)
	var deps []string
	for _, d := range seq(t["dependencies"]) {
		dm := mapping(d)
		deps = append(deps, firstNonEmpty(scalar(d), scalar(dm["role"]), scalar(dm["name"]), "a role"))
	}
	if len(deps) > 0 && !c.depsCalled {
		c.note(body, "dependencies", file, t["dependencies"].Line, "runs the roles "+strings.Join(deps, ", ")+" first; convert a playbook that runs this role, with -out, and they're converted and called before it")
	}
	if n := t["argument_specs"]; n != nil {
		c.note(body, "argument_specs", file, n.Line, "checks the role's arguments, which the converter doesn't carry over to variable types and validation yet")
	} else if _, err := os.Stat(c.path("meta/argument_specs.yml")); err == nil {
		c.note(body, "argument_specs", "meta/argument_specs.yml", 0, "checks the role's arguments, which the converter doesn't carry over to variable types and validation yet")
	}
}

// note records something about the whole role for review, as a comment at
// the top of main.circuit.hcl.
func (c *converter) note(body *hclwrite.Body, what, file string, line int, reason string) {
	c.res.Review = append(c.res.Review, Issue{Task: what, File: file, Line: line, Reason: reason})
	where := file
	if line > 0 {
		where = fmt.Sprintf("%s line %d", file, line)
	}
	comment(body, fmt.Sprintf("TODO(convert): %s (%s) %s.", what, where, reason))
}

// loopKey is the field a loop over maps is keyed by: name if the task
// needs it, else the first field it needs. Empty when it needs none.
func loopKey(fields map[string]*string) string {
	var need []string
	for f, d := range fields {
		if d == nil {
			need = append(need, f)
		}
	}
	if slices.Contains(need, "name") {
		return "name"
	}
	slices.Sort(need)
	if len(need) == 0 {
		return ""
	}
	return need[0]
}

// checkLoop says why a loop over the default k, reading fields from its
// items, can't convert: k read both as plain values and as maps, a field
// read with two defaults, an item without a field the loop needs, or no
// field to key the loop by.
func (r *role) checkLoop(k string, fields map[string]*string) string {
	if len(fields) == 0 {
		if r.mapFields[k] != nil {
			return fmt.Sprintf("loops over %q as plain values, where another task reads fields from its items", k)
		}
		return ""
	}
	if r.listUsed[k] {
		return fmt.Sprintf("reads fields from the items of %q, where another task loops over them as plain values", k)
	}
	if loopKey(fields) == "" {
		return fmt.Sprintf("reads only fields with a default from the items of %q, so there's no field every item has to tell the steps apart by", k)
	}
	for f, d := range fields {
		if old, seen := r.mapFields[k][f]; seen && old != nil && d != nil && *old != *d {
			return fmt.Sprintf("reads item.%s with the default %q, where another task gives it %q", f, *d, *old)
		}
		if d != nil {
			continue
		}
		for i, it := range r.maps[k] {
			if _, ok := it[f]; !ok {
				return fmt.Sprintf("reads item.%s, which item %d of %q doesn't have, so Ansible would stop there", f, i+1, k)
			}
		}
	}
	return ""
}

// useMapLoop records the fields a converted loop over k reads, which make
// up its variable's type, and returns the field it's keyed by.
func (r *role) useMapLoop(k string, fields map[string]*string) string {
	if r.mapFields[k] == nil {
		r.mapFields[k] = map[string]*string{}
	}
	for f, d := range fields {
		if old, seen := r.mapFields[k][f]; !seen || old != nil && d == nil {
			r.mapFields[k][f] = d // a bare read anywhere makes the field required
		}
	}
	key := loopKey(fields)
	if !slices.Contains(r.mapKeys[k], key) {
		r.mapKeys[k] = append(r.mapKeys[k], key)
	}
	return key
}

// mapList reads a default that's a list of maps whose values are plain,
// as plainValue reads each.
func mapList(n *yaml.Node) ([]map[string]string, bool) {
	if n == nil || n.Kind != yaml.SequenceNode || len(n.Content) == 0 {
		return nil, false
	}
	var items []map[string]string
	for _, e := range n.Content {
		if e.Kind != yaml.MappingNode {
			return nil, false
		}
		item := map[string]string{}
		for _, kv := range pairs(e) {
			v, _, why := plainValue(kv[1])
			if why != "" || !identifier.MatchString(kv[0].Value) {
				return nil, false
			}
			item[kv[0].Value] = v
		}
		items = append(items, item)
	}
	return items, true
}

// mapVariable writes the variable for a list of maps a loop reads: an
// object per item with the fields the loops read, and a check that each
// field a loop is keyed by is different in every item.
func (r *role) mapVariable(vb *hclwrite.Body, k, defaultsFile string) {
	fields := slices.Sorted(maps.Keys(r.mapFields[k]))
	var typ []string
	for _, f := range fields {
		if d := r.mapFields[k][f]; d != nil {
			typ = append(typ, fmt.Sprintf("%s = optional(string, \"%s\")", f, quoted(*d)))
		} else {
			typ = append(typ, f+" = string")
		}
	}
	b := vb.AppendNewBlock("variable", []string{k}).Body()
	b.SetAttributeRaw("type", rawTokens("list(object({ "+strings.Join(typ, ", ")+" }))"))
	if len(r.maps[k]) == 0 {
		b.SetAttributeRaw("default", rawTokens("[]"))
	} else {
		items := make([]cty.Value, len(r.maps[k]))
		for i, it := range r.maps[k] {
			obj := map[string]cty.Value{}
			for f, v := range it {
				obj[f] = cty.StringVal(v)
			}
			items[i] = cty.ObjectVal(obj)
		}
		b.SetAttributeValue("default", cty.TupleVal(items))
	}
	b.SetAttributeValue("description", cty.StringVal("From the role's "+defaultsFile+". Each item is one pass of the loop that uses it."))
	for _, f := range fields {
		pathValidations(b, k, f, r.pathRules[k+"."+f], false)
	}
	for _, key := range r.mapKeys[k] {
		v := b.AppendNewBlock("validation", nil).Body()
		v.SetAttributeRaw("condition", rawTokens(fmt.Sprintf("length(distinct([for i in var.%s : i.%s])) == length(var.%s)", k, key, k)))
		v.SetAttributeValue("error_message", cty.StringVal(fmt.Sprintf("Each item of %s needs its own %s: a step runs once per %s.", k, key, key)))
	}
}

// plainList reads a default that's a list of plain values, as plainValue
// reads each, all different, since a step's for_each refuses repeats.
func plainList(n *yaml.Node) ([]string, bool) {
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil, false
	}
	items := []string{}
	for _, e := range n.Content {
		v, _, why := plainValue(e)
		if why != "" || slices.Contains(items, v) {
			return nil, false
		}
		items = append(items, v)
	}
	return items, true
}

// plainValue reads a role variable as Ansible prints it into a string: plain
// text, or a whole number. Otherwise why says what it is. Ansible reads YAML
// 1.1, where yes is true and 0777 is 511, so a plain scalar counts as text
// only when it can't be read as anything else.
func plainValue(n *yaml.Node) (val string, number bool, why string) {
	if n == nil || n.Kind != yaml.ScalarNode {
		return "", false, "a list, a map or an alias"
	}
	v := n.Value
	if strings.Contains(v, "{{") || strings.Contains(v, "{%") {
		return "", false, "a Jinja expression"
	}
	// Ansible can read text like [1, 2] back as a list.
	if t := strings.TrimSpace(v); strings.HasPrefix(t, "[") || strings.HasPrefix(t, "{") {
		return "", false, "text that Ansible could read as a list or a map"
	}
	if n.Style&(yaml.SingleQuotedStyle|yaml.DoubleQuotedStyle|yaml.LiteralStyle|yaml.FoldedStyle) != 0 || n.Tag == "!!str" && n.Style&yaml.TaggedStyle != 0 {
		return v, false, ""
	}
	if wholeNumber.MatchString(v) {
		return v, true, ""
	}
	switch strings.ToLower(v) {
	case "y", "n":
		return "", false, "y or n, which Ansible reads as text: a bare when finds it true, but | bool reads n as false"
	case "", "~", "null", "yes", "no", "true", "false", "on", "off":
		return "", false, "true, false or empty"
	}
	if !textStart.MatchString(v) {
		return "", false, "a value YAML could read as a number or a date"
	}
	return v, false, ""
}

var (
	wholeNumber = regexp.MustCompile(`^(0|-?[1-9][0-9]*)$`)
	textStart   = regexp.MustCompile(`^[A-Za-z/]`)
)

// copy adds a file a task copies from the role to the circuit.
func (in *input) copy(p string) {
	b, err := os.ReadFile(filepath.Join(in.dir, p))
	if err != nil {
		in.fail(fmt.Sprintf("%s can't be read: %s", p, err))
		return
	}
	if in.out == nil {
		in.out = map[string][]byte{}
	}
	in.out[p] = b
}

// template rewrites a role's Jinja template in templatefile syntax, which
// works only when the template does nothing but print role variables with
// {{ name }}. It returns the new file's path in the circuit and the vars
// the template step passes it.
func (in *input) template(p string) (source, vars, why string) {
	b, err := os.ReadFile(filepath.Join(in.dir, p))
	if err != nil {
		return "", "", "can't be read: " + err.Error()
	}
	text := string(b)
	switch {
	case !utf8.ValidString(text):
		return "", "", "isn't UTF-8 text"
	case strings.Contains(text, "\r"):
		return "", "", "has Windows line endings, which Ansible writes as \\n"
	case strings.HasPrefix(text, "#jinja2:"):
		return "", "", "changes Jinja's settings in its first line"
	case strings.Contains(text, "{%") || strings.Contains(text, "{#"):
		return "", "", "uses Jinja statements or comments, {% %} or {# #}"
	}
	escape := strings.NewReplacer("${", "$${", "%{", "%%{")
	var out strings.Builder
	names := map[string]bool{}
	last := 0
	for _, m := range append(jinja.FindAllStringSubmatchIndex(text, -1), []int{len(text), len(text), 0, 0}) {
		lit := text[last:m[0]]
		if strings.Contains(lit, "{{") {
			return "", "", "uses a Jinja expression other than {{ name }}"
		}
		out.WriteString(escape.Replace(lit))
		if m[0] == len(text) {
			break
		}
		name := text[m[2]:m[3]]
		names[name] = true
		out.WriteString("${" + name + "}")
		last = m[1]
	}
	var lines []string
	for _, name := range sortedSet(names) {
		switch {
		case has(in.vars, name):
			lines = append(lines, name+" = "+string(hclwrite.TokensForValue(cty.StringVal(in.vars[name])).Bytes()))
		case in.role.defaults[name] != nil && in.role.defaults[name].boolean:
			// Ansible prints a boolean the Python way, True or False.
			return "", "", fmt.Sprintf("prints %q, a true-or-false default that Ansible writes as True or False and Conn3x as true or false", name)
		case in.role.defaults[name] != nil:
			lines = append(lines, name+" = var."+name)
		default:
			return "", "", fmt.Sprintf("refers to %q, which isn't a role variable the converter can fill in", name)
		}
	}
	if len(lines) > 0 {
		vars = "{\n" + strings.Join(lines, "\n") + "\n}"
	}
	source = strings.TrimSuffix(p, ".j2") + ".tftpl"
	if have, ok := in.role.files[source]; ok && string(have) != out.String() {
		return "", "", "would be written to " + source + ", where another template already is"
	}
	if in.out == nil {
		in.out = map[string][]byte{}
	}
	in.out[source] = []byte(out.String())
	return source, vars, ""
}

// pairs lists a mapping's keys and values in the order they're written.
func pairs(n *yaml.Node) [][2]*yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	var out [][2]*yaml.Node
	for i := 0; i+1 < len(n.Content); i += 2 {
		out = append(out, [2]*yaml.Node{n.Content[i], n.Content[i+1]})
	}
	return out
}

func has(m map[string]string, k string) bool { _, ok := m[k]; return ok }

func sortedSet(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func readme(base, name string, review int, order []string, defaults map[string]*roleDefault) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# circuit-%s\n\nA [Conn3x](https://conn3x.org) circuit converted from the Ansible role `%s` by `conn3x convert ansible -role`.\n\n", name, base)
	switch review {
	case 0:
		b.WriteString("Every task converted.\n\n")
	case 1:
		b.WriteString("One thing still needs you. It's marked `TODO(convert)` in `main.circuit.hcl`, with the reason.\n\n")
	default:
		fmt.Fprintf(&b, "%d things still need you. Each is marked `TODO(convert)` in `main.circuit.hcl`, with the reason.\n\n", review)
	}
	fmt.Fprintf(&b, "## Usage\n\n```hcl\nmodule %q {\n  source = \"./circuit-%s\"\n\n  hosts = {\n    web1 = \"203.0.113.10\"\n  }\n\n  ssh_private_key_file = \"~/.ssh/id_ed25519\"\n}\n```\n\nThen run `conn3x init` and `conn3x apply`.\n\n", name, name)
	b.WriteString("## Variables\n\n`hosts` and the `ssh_` variables say where to log in and how; see `variables.tf`.")
	if len(order) == 0 {
		b.WriteString("\n")
		return []byte(b.String())
	}
	b.WriteString(" The rest are the role's defaults:\n\n| Name | Default |\n| --- | --- |\n")
	for _, k := range order {
		d := defaults[k]
		v := d.value
		if !d.number && !d.boolean {
			v = string(hclwrite.TokensForValue(cty.StringVal(v)).Bytes())
		}
		fmt.Fprintf(&b, "| `%s` | `%s` |\n", k, strings.ReplaceAll(v, "|", `\|`))
	}
	return []byte(b.String())
}

// circuitVariables are the variables every circuit takes, as in the
// circuits at github.com/conn3xorg.
const circuitVariables = `variable "hosts" {
  type        = any
  description = "The hosts to configure: a map of names to addresses, or to host objects with an address and settings such as host_key."

  validation {
    condition     = can(keys(var.hosts)) && alltrue([for v in values(var.hosts) : can(tostring(v)) || can(tostring(v.address))])
    error_message = "hosts must be a map whose values are addresses, or objects with an address."
  }
}

variable "ssh_user" {
  type        = string
  default     = "root"
  description = "The user to log in as."
}

variable "ssh_port" {
  type        = number
  default     = 22
  description = "The SSH port."
}

variable "ssh_private_key_file" {
  type        = string
  default     = null
  description = "Path to a private key file. When null, Conn3x uses the SSH agent."
}

variable "ssh_known_hosts_file" {
  type        = string
  default     = null
  description = "The known_hosts file to check host keys against. When null, Conn3x uses ~/.ssh/known_hosts."
}

variable "ssh_become" {
  type        = bool
  default     = false
  description = "Run every command as root through sudo. Set this when ssh_user isn't root."
}
`

// whenUses notes what a converted when reads, so the circuit declares it:
// the installed packages, the family, or a list default.
func (r *role) whenUses(cond string) {
	if strings.Contains(cond, "data.conn3x_packages.") {
		r.packagesUsed = true
	}
	if strings.Contains(cond, "data.conn3x_host.") || strings.Contains(cond, "local.os_family[") {
		r.familyUsed = true
	}
	for _, m := range whenListRe.FindAllStringSubmatch(cond, -1) {
		if _, ok := r.lists[m[1]]; ok {
			r.listUsed[m[1]] = true
		}
	}
}

// boolWhen is a role task's when as a step's when, for the shapes a role
// uses to switch a feature on a default that's true or false: the default
// itself, through the bool filter, or either negated, as
// apache_create_vhosts | bool or not (ntp_enabled | bool). It also takes
// a text default compared to text, as docker_install_method == 'package'.
// A default can't change during a run, so either reads the same anywhere,
// and neither can a probe's result, read once at plan time, so a when on
// one converts here too. "" for any other when.
func (r *role) boolWhen(n *yaml.Node) string {
	if n.Kind != yaml.ScalarNode {
		return ""
	}
	cond := strings.Join(strings.Fields(n.Value), " ")
	if p := r.probeWhen(cond); p != "" {
		return p
	}
	if m := textWhenRe.FindStringSubmatch(cond); m != nil {
		if d, ok := r.defaults[m[1]]; !ok || d.boolean || d.number {
			return ""
		}
		return fmt.Sprintf("var.%s %s \"%s\"", m[1], m[2], quoted(m[3]+m[4]))
	}
	m := boolWhenRe.FindStringSubmatch(cond)
	if m == nil {
		return ""
	}
	name := m[2] + m[3]
	if d, ok := r.defaults[name]; !ok || !d.boolean {
		return ""
	}
	if m[1] != "" {
		return "!var." + name
	}
	return "var." + name
}

var textWhenRe = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*) ?(==|!=) ?(?:'([^'\\]*)'|"([^"\\]*)")$`)

var boolWhenRe = regexp.MustCompile(`^(not )?(?:\(([A-Za-z_][A-Za-z0-9_]*) ?\| ?bool\)|([A-Za-z_][A-Za-z0-9_]*)(?: ?\| ?bool)?)$`)

// yamlBool reads a plain scalar as Ansible's YAML loader, PyYAML, does:
// yes, no, on and off are booleans too, in lower, title or upper case.
// y and n aren't, though YAML 1.1 lists them, and neither is a mixed case
// such as yEs: Ansible reads those as text, which a bare when finds true.
func yamlBool(n *yaml.Node) (bool, bool) {
	if n == nil || n.Kind != yaml.ScalarNode || n.Style != 0 {
		return false, false
	}
	switch n.Value {
	case "yes", "Yes", "YES", "true", "True", "TRUE", "on", "On", "ON":
		return true, true
	case "no", "No", "NO", "false", "False", "FALSE", "off", "Off", "OFF":
		return false, true
	}
	return false, false
}

// pathValidations adds the validations a default used in a path needs,
// each item of it when list, or field of each item when field is set.
func pathValidations(b *hclwrite.Body, k, field string, rules []string, list bool) {
	for _, rule := range []string{"abs", "noslash"} {
		if !slices.Contains(rules, rule) {
			continue
		}
		cond, msg := `startswith(%s, "/")`, "an absolute path, starting with /"
		if rule == "noslash" {
			cond, msg = `!endswith(%s, "/")`, "a path that doesn't end in /, which Ansible reads as a directory to write into"
		}
		v := b.AppendNewBlock("validation", nil).Body()
		if field != "" {
			v.SetAttributeRaw("condition", rawTokens(fmt.Sprintf("alltrue([for i in var.%s : "+cond+"])", k, "i."+field)))
			v.SetAttributeValue("error_message", cty.StringVal("Each item's "+field+" in "+k+" goes in a path, so it must be "+msg+"."))
		} else if list {
			v.SetAttributeRaw("condition", rawTokens(fmt.Sprintf("alltrue([for p in var.%s : "+cond+"])", k, "p")))
			v.SetAttributeValue("error_message", cty.StringVal("Each item of "+k+" goes in a path, so it must be "+msg+"."))
		} else {
			v.SetAttributeRaw("condition", rawTokens(fmt.Sprintf(cond, "var."+k)))
			v.SetAttributeValue("error_message", cty.StringVal(k+" goes in a path, so it must be "+msg+"."))
		}
	}
}

// isFamilyInclude reports whether node, in file, is the role's include of its
// per-family variables.
func (r *role) isFamilyInclude(node *yaml.Node, file string) bool {
	if r == nil {
		return false
	}
	for _, inc := range r.varsIncludes {
		if node == inc.node {
			return true
		}
	}
	return slices.Contains(r.familyIncludeAt, fmt.Sprintf("%s:%d", file, node.Line))
}
