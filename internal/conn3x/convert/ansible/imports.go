// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// taskAt is a task and the file it came from, relative to the converter's
// dir. reason is set when it's an include the converter can't inline.
type taskAt struct {
	node   *yaml.Node
	file   string
	reason string
}

// importKeys are what an import_tasks may set and still be inlined. Any other
// keyword, such as when, become or vars, would apply to every task it imports.
var importKeys = map[string]bool{"name": true, "tags": true}

// flatten inlines static imports, so their tasks convert as if written in
// place, the way Ansible reads them before the play starts. stack holds the
// files being read, to catch a file that imports itself.
func (c *converter) flatten(nodes []*yaml.Node, file string, stack []string) []taskAt {
	var out []taskAt
	for _, n := range nodes {
		mod, args := moduleOf(mapping(n))
		switch mod {
		case "import_tasks":
			sub, tasks, why := c.importFile(n, args, file, stack)
			if why != "" {
				out = append(out, taskAt{node: n, file: file, reason: why})
				continue
			}
			out = append(out, c.flatten(tasks, sub, append(stack, sub))...)
		case "include_tasks", "include":
			if tasks, ok := c.familyInclude(n, args, file, stack); ok {
				out = append(out, tasks...)
				continue
			}
			out = append(out, taskAt{node: n, file: file, reason: "uses " + mod + ", which Ansible reads only when the play reaches it, so its file, loop and when can change from run to run; the converter can't translate that yet. If it names one file and has no loop or when, change it to import_tasks and convert again"})
		case "include_role", "import_role":
			out = append(out, taskAt{node: n, file: file, reason: "uses " + mod + ", which runs another role here; convert that role with -role and call its circuit as a module"})
		default:
			out = append(out, taskAt{node: n, file: file})
		}
	}
	return out
}

// importFile finds and reads the file an import_tasks names. Ansible looks
// beside the file doing the importing, and in a role, in its tasks/.
func (c *converter) importFile(n *yaml.Node, args map[string]*yaml.Node, file string, stack []string) (string, []*yaml.Node, string) {
	for _, k := range sortedKeys(mapping(n)) {
		if keywords[k] && !importKeys[k] {
			return "", nil, "sets " + k + " on import_tasks, which applies it to every task it imports; the converter can't translate that yet"
		}
	}
	name := scalar(args["file"])
	if raw := scalar(args["_raw"]); raw != "" && len(args) == 1 {
		name = raw
	} else if len(args) != 1 || name == "" {
		return "", nil, "has an import_tasks without a single file to read"
	}
	if strings.Contains(name, "{{") || strings.Contains(name, "{%") {
		return "", nil, "names the file to import with a Jinja expression, which the converter can't translate"
	}
	dirs := []string{filepath.Dir(file)}
	if c.role != nil {
		dirs = append(dirs, "tasks")
	}
	var found []string
	for _, d := range dirs {
		p := filepath.Clean(filepath.Join(d, name))
		if filepath.IsAbs(name) {
			p = name
		}
		if _, err := os.Stat(c.path(p)); err == nil && !slices.Contains(found, p) {
			found = append(found, p)
		}
	}
	switch {
	case len(found) == 0:
		return "", nil, fmt.Sprintf("imports %s, which wasn't found beside %s", name, file)
	case len(found) > 1:
		return "", nil, fmt.Sprintf("imports %s, and both %s exist; the converter can't tell which Ansible would read", name, strings.Join(found, " and "))
	case slices.Contains(stack, found[0]):
		return "", nil, fmt.Sprintf("imports %s, which is already being imported, so it would never finish", found[0])
	}
	src, err := os.ReadFile(c.path(found[0]))
	if err != nil {
		return "", nil, fmt.Sprintf("imports %s, which can't be read: %s", found[0], err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return "", nil, fmt.Sprintf("imports %s, which isn't valid YAML: %s", found[0], err)
	}
	if len(doc.Content) == 0 {
		return found[0], nil, ""
	}
	if doc.Content[0].Kind != yaml.SequenceNode {
		return "", nil, fmt.Sprintf("imports %s, which isn't a list of tasks", found[0])
	}
	return found[0], doc.Content[0].Content, ""
}

// path is where a file relative to the converter's dir is on disk.
func (c *converter) path(rel string) string {
	if filepath.IsAbs(rel) {
		return rel
	}
	return filepath.Join(c.dir, rel)
}
