// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package facts

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
)

// LocalDirs are where a host keeps facts about itself: Conn3x's own, then
// Ansible's, so a host set up for Ansible's local facts needs no change.
// A name in the first wins over the same name in the second.
var LocalDirs = []struct{ Dir, Ext string }{{"/etc/conn3x/facts.d", ".json"}, {"/etc/ansible/facts.d", ".fact"}}

// LocalTimeout is how long an executable fact file may run, in seconds.
const LocalTimeout = 10

// localScript prints, for each fact file, its path and then its content, or
// an executable one's output, in base64 on one line, so any byte survives.
// A file that can't be read or run prints "!" and the reason instead.
var localScript = func() string {
	var globs []string
	for _, d := range LocalDirs {
		globs = append(globs, d.Dir+"/*"+d.Ext)
	}
	return fmt.Sprintf(`for f in %s; do
  [ -f "$f" ] || continue
  echo "$f"
  if [ -x "$f" ]; then
    if out=$(timeout %d "$f" 2>&1); then printf '%%s' "$out" | base64 | tr -d '\n'; echo
    else echo "!it exited with an error: $(printf '%%s' "$out" | head -c 200 | tr '\n' ' ')"; fi
  elif [ -r "$f" ]; then base64 < "$f" | tr -d '\n'; echo
  else echo "!it can't be read"; fi
done`, strings.Join(globs, " "), LocalTimeout)
}()

// factName is what a fact file's name may be, without its extension: what
// a circuit can read as an attribute.
var factName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)

// Local reads a host's local facts, as JSON text by fact name: the file's
// name without its extension. A .fact file may be JSON or INI, as Ansible
// reads it; INI becomes an object of sections, each an object of strings.
func Local(ctx context.Context, r modules.Runner) (map[string][]byte, error) {
	res, err := r.Run(ctx, localScript, nil)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("reading local facts: %s", strings.TrimSpace(string(res.Stderr)))
	}
	return parseLocal(string(res.Stdout))
}

func parseLocal(out string) (map[string][]byte, error) {
	facts := map[string][]byte{}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return facts, nil
	}
	if len(lines)%2 != 0 {
		return nil, fmt.Errorf("reading local facts: unexpected output")
	}
	for i := 0; i < len(lines); i += 2 {
		file, data := lines[i], lines[i+1]
		ext := path.Ext(file)
		name := strings.TrimSuffix(path.Base(file), ext)
		if !factName.MatchString(name) {
			return nil, fmt.Errorf("local fact file %s: name it with letters, digits, _ and - only, starting with a letter, so a circuit can read it", file)
		}
		if _, seen := facts[name]; seen {
			continue // the Conn3x directory comes first
		}
		if why, failed := strings.CutPrefix(data, "!"); failed {
			return nil, fmt.Errorf("local fact file %s: %s", file, why)
		}
		raw, err := base64.StdEncoding.DecodeString(data)
		if err != nil {
			return nil, fmt.Errorf("local fact file %s: %w", file, err)
		}
		v, err := localValue(raw, ext == ".fact")
		if err != nil {
			return nil, fmt.Errorf("local fact file %s: %w", file, err)
		}
		facts[name] = v
	}
	return facts, nil
}

// localValue is a fact file's content as JSON. With ini set, content that
// isn't JSON is read as INI. Where Ansible would store an error message as
// the fact and carry on, this is an error, so a plan never reads a message
// as a value.
func localValue(raw []byte, ini bool) ([]byte, error) {
	if json.Valid(raw) {
		return raw, nil
	}
	if !ini {
		return nil, fmt.Errorf("it isn't valid JSON")
	}
	sections := map[string]map[string]string{}
	var cur map[string]string
	for n, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";"):
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			name := strings.TrimSpace(line[1 : len(line)-1])
			if sections[name] == nil {
				sections[name] = map[string]string{}
			}
			cur = sections[name]
		default:
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				k, v, ok = strings.Cut(line, ":")
			}
			if !ok || cur == nil {
				return nil, fmt.Errorf("it's neither JSON nor INI: line %d is %q", n+1, line)
			}
			cur[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v) // as Python's ConfigParser, which Ansible uses
		}
	}
	return json.Marshal(sections)
}
