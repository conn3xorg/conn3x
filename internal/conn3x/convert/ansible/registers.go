package ansible

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// cacheOnly reports whether a task only refreshes the package lists, as
// apt: update_cache=yes does. Conn3x refreshes them itself after writing a
// repository and when a package isn't found, so such a task has nothing to
// convert into, whatever its when says.
func cacheOnly(t map[string]*yaml.Node) bool {
	mod, args := moduleOf(t)
	switch mod {
	case "apt", "yum", "dnf", "dnf5", "package":
	default:
		return false
	}
	for k := range t {
		if keywords[k] && k != "name" && k != "when" && k != "tags" {
			return false
		}
	}
	if b, ok := yamlBool(args["update_cache"]); !ok || !b {
		return false
	}
	for k := range args {
		if k != "update_cache" && k != "cache_valid_time" && k != "_raw" {
			return false
		}
	}
	return true
}

// findUnreadRegisters records the tasks whose register nothing in the role
// reads: no task, handler or template names it, other than a cacheOnly
// task's when, which is dropped. register then changes nothing a circuit
// would do, so it doesn't stop the task converting. It records too the
// names that are read only as R is changed or R.changed, which
// applyTimeWhen turns into triggers on the registering task's step.
func (c *converter) findUnreadRegisters(tasks []taskAt) {
	c.unreadRegister = map[*yaml.Node]bool{}
	c.changedOnly = map[string]bool{}
	if c.role == nil {
		return
	}
	var text strings.Builder
	_ = filepath.WalkDir(c.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			if d != nil && d.IsDir() && d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if b, err := os.ReadFile(p); err == nil {
			text.Write(b)
			text.WriteByte('\n')
		}
		return nil
	})
	all := text.String()
	for _, t := range tasks {
		m := mapping(t.node)
		name := scalar(m["register"])
		if !identifier.MatchString(name) {
			continue
		}
		word := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`)
		registers := len(regexp.MustCompile(`register:\s*["']?`+regexp.QuoteMeta(name)+`\b`).FindAllStringIndex(all, -1))
		reads := len(word.FindAllStringIndex(all, -1)) - registers
		changedRead := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `(?: is changed\b|\.changed\b)`)
		changed := len(changedRead.FindAllStringIndex(all, -1))
		// A file imported twice is in tasks twice; its text is in all once.
		seen := map[string]bool{}
		for _, o := range tasks {
			at := fmt.Sprintf("%s:%d", o.file, o.node.Line)
			if om := mapping(o.node); cacheOnly(om) && om["when"] != nil && !seen[at] {
				seen[at] = true
				reads -= len(word.FindAllStringIndex(nodeText(om["when"]), -1))
				changed -= len(changedRead.FindAllStringIndex(nodeText(om["when"]), -1))
			}
		}
		if reads <= 0 {
			c.unreadRegister[t.node] = true
		} else if reads == changed && registers == 1 && !probeShaped(m) {
			c.changedOnly[name] = true
		}
	}
}

// nodeText is every scalar under n, one per line.
func nodeText(n *yaml.Node) string {
	if n == nil {
		return ""
	}
	if n.Kind == yaml.ScalarNode {
		return n.Value + "\n"
	}
	var b strings.Builder
	for _, k := range n.Content {
		b.WriteString(nodeText(k))
	}
	return b.String()
}
