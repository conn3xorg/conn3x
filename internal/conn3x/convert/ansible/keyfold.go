package ansible

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// keyPairs finds each apt_key or rpm_key task that only imports the key the
// repository task right after it is signed with. A repository step takes the
// key and the repository together, so the key task folds into that step.
func (c *converter) keyPairs(tasks []taskAt) {
	c.keyFolded, c.keyFrom = map[*yaml.Node]string{}, map[*yaml.Node]string{}
	for i := 0; i+1 < len(tasks); i++ {
		from, mod := keyImport(tasks[i].node)
		if from == "" {
			continue
		}
		next := tasks[i+1].node
		nextMod, args := moduleOf(mapping(next))
		switch {
		case mod == "apt_key" && nextMod == "apt_repository":
			// Only a line with no signed-by= relies on the keyring apt_key wrote.
			if strings.Contains(scalar(args["repo"]), "signed-by=") {
				continue
			}
			c.keyFrom[next] = from
		case mod == "rpm_key" && nextMod == "yum_repository":
			if oneScalar(args["gpgkey"]) != from {
				continue
			}
		default:
			continue
		}
		c.keyFolded[tasks[i].node] = from
	}
}

// keyImport is the URL or path an apt_key or rpm_key task imports, when that
// is all it does: no condition, loop, keyserver lookup or other keyring.
func keyImport(node *yaml.Node) (from, mod string) {
	t := mapping(node)
	mod, args := moduleOf(t)
	field := map[string]string{"apt_key": "url", "rpm_key": "key"}[mod]
	if field == "" {
		return "", ""
	}
	for k := range t {
		if k != "name" && k != "tags" && k != "become" && k[strings.LastIndex(k, ".")+1:] != mod {
			return "", ""
		}
	}
	for k, v := range args {
		if k != field && (k != "state" || scalar(v) != "present") {
			return "", ""
		}
	}
	from = scalar(args[field])
	if strings.Contains(from, "{{") {
		return "", ""
	}
	return from, mod
}

// oneScalar is a value given as a string or as a list of one string.
func oneScalar(n *yaml.Node) string {
	if n != nil && n.Kind == yaml.SequenceNode && len(n.Content) == 1 {
		n = n.Content[0]
	}
	return scalar(n)
}

// A key task that reaches a module function didn't fold into a repository.
func aptKeyModule(in *input) ([]step, string) {
	if in.has("keyserver") || in.has("id") && !in.has("url") {
		return nil, "looks the key up on a keyserver; a repository step needs the armored key itself, so download it, save it under files/ and give it to the repository task"
	}
	return nil, fmt.Sprintf("imports a key into apt's shared keyring (apt_key is deprecated), which trusts it for every repository; a repository step takes the key with the repository it signs, and the converter folds the two only when this task sets just url and the next task is the apt_repository it signs, without signed-by%s", keyOnlyHint(in))
}

func rpmKeyModule(in *input) ([]step, string) {
	return nil, fmt.Sprintf("imports a key into rpm's database, which trusts it for every repository; a repository step takes the key with the repository it signs, and the converter folds the two only when this task sets just key and the next task is a yum_repository with that gpgkey%s", keyOnlyHint(in))
}

func keyOnlyHint(in *input) string {
	if in.has("state") && scalar(in.args["state"]) == "absent" {
		return "; removing a key stays for a person"
	}
	return ""
}
