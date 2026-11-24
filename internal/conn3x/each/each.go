// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package each finds the root configurations under a directory, what each
// one reads from another, and which a change touched, for conn3x each.
//
// A configuration reads another when its terraform_remote_state names the
// state the other's backend writes: same backend type and the same
// identifying settings, such as an s3 bucket and key. Where that can't be
// worked out, because either side isn't a literal, conn3x.each.hcl in the
// reading configuration's directory can say so with depends_on.
package each

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// FileName is the optional file in a configuration's directory that names
// what it depends on, and files outside it that it reads.
const FileName = "conn3x.each.hcl"

// stateKeys are the settings that identify a backend's state, by type.
var stateKeys = map[string][]string{
	"s3":      {"bucket", "key"},
	"gcs":     {"bucket", "prefix"},
	"azurerm": {"storage_account_name", "container_name", "key"},
	"local":   {"path"},
}

// Config is one directory of configuration.
type Config struct {
	// Dir is the directory, slash-separated and relative to the root, "."
	// for the root itself.
	Dir string
	// State identifies the state its backend writes, or is "" when it
	// can't be worked out.
	State string
	// HasBackend is whether it has a backend block of its own.
	HasBackend bool
	// Reads identify the states its terraform_remote_state data sources
	// read.
	Reads []string
	// Unresolved names the terraform_remote_state data sources whose state
	// can't be worked out, because their settings aren't literals.
	Unresolved []string
	// Modules are the local directories its module blocks call.
	Modules []string
	// DependsOn and Watch come from conn3x.each.hcl: configurations it
	// depends on, and paths outside its directory that it reads.
	DependsOn, Watch []string
}

// Tree is every configuration under a root.
type Tree struct {
	Root    string
	Configs map[string]*Config
	// Edges maps a root configuration to the root configurations it
	// depends on.
	Edges map[string][]string
	// Problems are things the tree couldn't work out, one line each.
	Problems []string
}

// skipDirs are directories that never hold a configuration of ours.
var skipDirs = map[string]bool{".git": true, ".terraform": true, "node_modules": true}

// Load reads every directory under root that holds .tf, .tofu or .circuit.hcl
// files.
func Load(root string) (*Tree, error) {
	t := &Tree{Root: root, Configs: map[string]*Config{}, Edges: map[string][]string{}}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		if p != root && (skipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".")) {
			return filepath.SkipDir
		}
		rel, _ := filepath.Rel(root, p)
		c, err := readDir(p, filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		if c != nil {
			t.Configs[c.Dir] = c
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	t.link()
	return t, nil
}

func readDir(dir, rel string) (*Config, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if n := e.Name(); !e.IsDir() && (strings.HasSuffix(n, ".tf") || strings.HasSuffix(n, ".tofu") || strings.HasSuffix(n, ".circuit.hcl")) {
			files = append(files, n)
		}
	}
	if len(files) == 0 {
		return nil, nil
	}
	c := &Config{Dir: rel}
	parser := hclparse.NewParser()
	for _, n := range files {
		f, diags := parser.ParseHCLFile(filepath.Join(dir, n))
		if diags.HasErrors() {
			return nil, fmt.Errorf("%s: %s", path.Join(rel, n), diags.Error())
		}
		body, ok := f.Body.(*hclsyntax.Body)
		if !ok {
			continue
		}
		for _, b := range body.Blocks {
			switch {
			case b.Type == "terraform":
				for _, inner := range b.Body.Blocks {
					if inner.Type == "backend" && len(inner.Labels) == 1 {
						c.HasBackend = true
						c.State = stateID(inner.Labels[0], literalAttrs(inner.Body.Attributes), rel)
					}
				}
			case b.Type == "module":
				if a, ok := b.Body.Attributes["source"]; ok {
					if s, ok := literalString(a.Expr); ok && (strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../")) {
						c.Modules = append(c.Modules, path.Clean(path.Join(rel, s)))
					}
				}
			case b.Type == "data" && len(b.Labels) == 2 && b.Labels[0] == "terraform_remote_state":
				id := ""
				if a, ok := b.Body.Attributes["backend"]; ok {
					if typ, ok := literalString(a.Expr); ok {
						settings := map[string]string{}
						if cfg, ok := b.Body.Attributes["config"]; ok {
							settings = literalObject(cfg.Expr)
						}
						id = stateID(typ, settings, rel)
					}
				}
				if id == "" {
					c.Unresolved = append(c.Unresolved, b.Labels[1])
				} else {
					c.Reads = append(c.Reads, id)
				}
			}
		}
	}
	if !c.HasBackend {
		// No backend is local state in the directory itself.
		c.State = stateID("local", map[string]string{"path": "terraform.tfstate"}, rel)
	}
	if err := readEachFile(dir, c); err != nil {
		return nil, err
	}
	return c, nil
}

// readEachFile reads conn3x.each.hcl, when there is one.
func readEachFile(dir string, c *Config) error {
	p := filepath.Join(dir, FileName)
	if _, err := os.Stat(p); err != nil {
		return nil
	}
	f, diags := hclparse.NewParser().ParseHCLFile(p)
	if diags.HasErrors() {
		return fmt.Errorf("%s: %s", path.Join(c.Dir, FileName), diags.Error())
	}
	content, diags := f.Body.Content(&hcl.BodySchema{Attributes: []hcl.AttributeSchema{{Name: "depends_on"}, {Name: "watch"}}})
	if diags.HasErrors() {
		return fmt.Errorf("%s: %s", path.Join(c.Dir, FileName), diags.Error())
	}
	for name, into := range map[string]*[]string{"depends_on": &c.DependsOn, "watch": &c.Watch} {
		a, ok := content.Attributes[name]
		if !ok {
			continue
		}
		v, diags := a.Expr.Value(nil)
		if diags.HasErrors() || (!v.Type().IsTupleType() && !v.Type().IsListType()) {
			return fmt.Errorf("%s: %s must be a list of paths", path.Join(c.Dir, FileName), name)
		}
		for _, e := range v.AsValueSlice() {
			if e.Type() != cty.String || e.IsNull() {
				return fmt.Errorf("%s: %s must be a list of paths", path.Join(c.Dir, FileName), name)
			}
			*into = append(*into, path.Clean(path.Join(c.Dir, e.AsString())))
		}
	}
	return nil
}

// stateID identifies a state by backend type and its identifying settings,
// or is "" when they aren't all known. A local path is made relative to the
// root, from the directory that names it.
func stateID(typ string, settings map[string]string, dir string) string {
	keys, ok := stateKeys[typ]
	if !ok {
		return ""
	}
	parts := []string{typ}
	for _, k := range keys {
		v, ok := settings[k]
		if !ok {
			if typ == "local" && k == "path" {
				v = "terraform.tfstate"
			} else {
				return ""
			}
		}
		if typ == "local" {
			v = path.Clean(path.Join(dir, v))
		}
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, " ")
}

func literalString(e hcl.Expression) (string, bool) {
	v, diags := e.Value(nil)
	if diags.HasErrors() || v.IsNull() || !v.IsKnown() || v.Type() != cty.String {
		return "", false
	}
	return v.AsString(), true
}

func literalAttrs(attrs hclsyntax.Attributes) map[string]string {
	out := map[string]string{}
	for name, a := range attrs {
		if s, ok := literalString(a.Expr); ok {
			out[name] = s
		}
	}
	return out
}

func literalObject(e hcl.Expression) map[string]string {
	out := map[string]string{}
	v, diags := e.Value(nil)
	if diags.HasErrors() || v.IsNull() || !v.IsKnown() || (!v.Type().IsObjectType() && !v.Type().IsMapType()) {
		return out
	}
	for k, val := range v.AsValueMap() {
		if val.Type() == cty.String && !val.IsNull() && val.IsKnown() {
			out[k] = val.AsString()
		}
	}
	return out
}

// IsRoot reports whether a configuration is run on its own: one nothing
// calls as a module, or one with a backend of its own even if something
// does.
func (t *Tree) IsRoot(dir string) bool {
	c := t.Configs[dir]
	if c == nil {
		return false
	}
	if c.HasBackend {
		return true
	}
	for _, other := range t.Configs {
		for _, m := range other.Modules {
			if m == dir {
				return false
			}
		}
	}
	return true
}

// Roots are the root configurations, sorted.
func (t *Tree) Roots() []string {
	var out []string
	for dir := range t.Configs {
		if t.IsRoot(dir) {
			out = append(out, dir)
		}
	}
	sort.Strings(out)
	return out
}

// link works out which root configuration depends on which.
func (t *Tree) link() {
	byState := map[string]string{}
	for _, dir := range t.Roots() {
		if s := t.Configs[dir].State; s != "" {
			byState[s] = dir
		}
	}
	for _, dir := range t.Roots() {
		c := t.Configs[dir]
		seen := map[string]bool{}
		add := func(d string) {
			if d != dir && !seen[d] {
				seen[d] = true
				t.Edges[dir] = append(t.Edges[dir], d)
			}
		}
		for _, s := range c.Reads {
			if d, ok := byState[s]; ok {
				add(d)
			}
		}
		for _, d := range c.DependsOn {
			if t.IsRoot(d) {
				add(d)
			} else {
				t.Problems = append(t.Problems, fmt.Sprintf("%s: %s names %s in depends_on, which isn't a root configuration", dir, FileName, d))
			}
		}
		for _, name := range c.Unresolved {
			t.Problems = append(t.Problems, fmt.Sprintf("%s: couldn't work out which configuration data.terraform_remote_state.%s reads, since its settings aren't literals; name it in depends_on in %s", dir, name, path.Join(dir, FileName)))
		}
		sort.Strings(t.Edges[dir])
	}
}

// files are the directories and paths a configuration's result depends on:
// its own directory, the local modules it calls at any depth, and what
// conn3x.each.hcl watches.
func (t *Tree) files(dir string) []string {
	out := []string{dir}
	seen := map[string]bool{dir: true}
	var walk func(string)
	walk = func(d string) {
		c := t.Configs[d]
		if c == nil {
			return
		}
		for _, m := range c.Modules {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
				walk(m)
			}
		}
	}
	walk(dir)
	if c := t.Configs[dir]; c != nil {
		out = append(out, c.Watch...)
	}
	return out
}

// Changed is the root configurations a change to these files touches,
// directly or through what they depend on: a configuration whose inputs
// may have moved is planned too. files are slash-separated, relative to
// the root.
func (t *Tree) Changed(files []string) []string {
	direct := map[string]bool{}
	for _, dir := range t.Roots() {
		for _, prefix := range t.files(dir) {
			for _, f := range files {
				if under(f, prefix) {
					direct[dir] = true
				}
			}
		}
	}
	// Anything depending on a changed configuration, at any distance.
	for grew := true; grew; {
		grew = false
		for dir, deps := range t.Edges {
			if direct[dir] {
				continue
			}
			for _, d := range deps {
				if direct[d] {
					direct[dir], grew = true, true
					break
				}
			}
		}
	}
	var out []string
	for dir := range direct {
		out = append(out, dir)
	}
	sort.Strings(out)
	return out
}

// under reports whether file is prefix or inside it.
func under(file, prefix string) bool {
	if prefix == "." {
		return true
	}
	return file == prefix || strings.HasPrefix(file, prefix+"/")
}

// Levels orders dirs so each level depends only on earlier ones; within
// a level nothing depends on anything else. A dependency outside dirs
// doesn't hold anything back. It's an error when dirs depend on each
// other in a cycle.
func (t *Tree) Levels(dirs []string) ([][]string, error) {
	in := map[string]bool{}
	for _, d := range dirs {
		in[d] = true
	}
	done := map[string]bool{}
	var levels [][]string
	for len(done) < len(dirs) {
		var level []string
		for _, d := range dirs {
			if done[d] {
				continue
			}
			ready := true
			for _, dep := range t.Edges[d] {
				if in[dep] && !done[dep] {
					ready = false
				}
			}
			if ready {
				level = append(level, d)
			}
		}
		if len(level) == 0 {
			var left []string
			for _, d := range dirs {
				if !done[d] {
					left = append(left, d)
				}
			}
			return nil, fmt.Errorf("these configurations depend on each other in a cycle: %s", strings.Join(left, ", "))
		}
		sort.Strings(level)
		for _, d := range level {
			done[d] = true
		}
		levels = append(levels, level)
	}
	return levels, nil
}
