// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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
	files     map[string][]byte // files for the circuit directory besides the HCL
	commaFree map[string]bool   // defaults used as package names
}

type roleDefault struct {
	value  string
	number bool
}

// reserved are variable names the circuit already uses or HCL won't take.
var reserved = map[string]bool{
	"hosts": true, "ssh_user": true, "ssh_port": true, "ssh_private_key_file": true,
	"ssh_known_hosts_file": true, "ssh_become": true, "source": true, "version": true,
	"providers": true, "count": true, "for_each": true, "lifecycle": true, "depends_on": true, "locals": true,
}

// ConvertRole reads the Ansible role in dir and translates it into the files
// of a circuit directory.
func ConvertRole(dir string) (Result, error) {
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
	r := &role{defaults: map[string]*roleDefault{}, files: map[string][]byte{}, commaFree: map[string]bool{}}
	c := &converter{dir: dir, role: r}

	f := hclwrite.NewEmptyFile()
	body := f.Body()
	comment(body, fmt.Sprintf("Converted from the Ansible role %s by conn3x convert ansible.", base))
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
	var order []string
	for _, kv := range pairs(defaultsNode) {
		k := kv[0].Value
		where := fmt.Sprintf("Default %q (%s line %d)", k, defaultsFile, kv[0].Line)
		v, number, why := plainValue(kv[1])
		switch {
		case has(vars, k):
			why = "is also set in " + varsFile + ", which wins in Ansible, so it stays fixed"
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
		r.defaults[k] = &roleDefault{value: v, number: number}
		order = append(order, k)
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
	c.steps(cb, seq(tasks), seq(handlers), handlersFile, false, vars)

	for _, k := range order {
		d := r.defaults[k]
		b := hclwrite.NewBlock("variable", []string{k})
		if d.number {
			b.Body().SetAttributeRaw("type", rawTokens("number"))
			b.Body().SetAttributeRaw("default", rawTokens(d.value))
		} else {
			b.Body().SetAttributeRaw("type", rawTokens("string"))
			b.Body().SetAttributeValue("default", cty.StringVal(d.value))
		}
		b.Body().SetAttributeValue("description", cty.StringVal("From the role's "+defaultsFile+"."))
		if r.commaFree[k] {
			v := b.Body().AppendNewBlock("validation", nil).Body()
			v.SetAttributeRaw("condition", rawTokens(fmt.Sprintf(`!strcontains(var.%s, ",")`, k)))
			v.SetAttributeValue("error_message", cty.StringVal(k+" names one package, so it can't have a comma; Ansible would read one as a list."))
		}
		vb.AppendNewline()
		vb.AppendBlock(b)
	}

	files := r.files
	files["main.circuit.hcl"] = hclwrite.Format(f.Bytes())
	files["variables.tf"] = append([]byte(circuitVariables), hclwrite.Format(vf.Bytes())...)
	files["outputs.tf"] = []byte("# An Ansible role has no outputs. Add any you want callers to read here.\n")
	files["README.md"] = readme(base, name, len(c.res.Review), order, r.defaults)
	c.res.Files = files
	return c.res, nil
}

var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// main reads a role's sub/main.yml, or .yaml, or main, as Ansible does,
// returning the document and the file it read.
func (c *converter) main(body *hclwrite.Body, sub string) (*yaml.Node, string) {
	for _, n := range []string{"main.yml", "main.yaml", "main"} {
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
			err = yaml.Unmarshal(src, &doc)
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
	if len(deps) > 0 {
		c.note(body, "dependencies", file, t["dependencies"].Line, "runs the roles "+strings.Join(deps, ", ")+" first; convert each with -role and call its circuit as a module beside this one, with depends_on")
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
	case "", "~", "null", "yes", "no", "true", "false", "on", "off", "y", "n":
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
		if !d.number {
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
