// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
	"gopkg.in/yaml.v3"
)

// A playbook edits a JSON file by reading it with slurp, then writing it
// back with copy, the content run through community.general.json_patch:
//
//	- slurp: { src: /etc/app.json }
//	  register: app
//	- copy:
//	    dest: /etc/app.json
//	    content: "{{ app.content | b64decode | from_json
//	      | community.general.json_patch('add', '/server/port', 9090)
//	      | to_nice_json }}"
//
// Each add, replace or remove on an object key becomes a json_value step,
// and the slurp, which only feeds the copy, a comment.

// jsonEdit is one json_patch operation as a json_value step.
type jsonEdit struct {
	key    string
	value  cty.Value // unset for a removal
	remove bool
}

var (
	jsonChainHead = regexp.MustCompile(`^\{\{-?\s*([A-Za-z_][A-Za-z0-9_]*)\.content\s*\|\s*(?:ansible\.builtin\.)?b64decode\s*\|\s*(?:ansible\.builtin\.)?from_json\s*`)
	jsonPatchCall = regexp.MustCompile(`^\|\s*(?:community\.general\.)?json_patch\s*\(`)
	jsonChainTail = regexp.MustCompile(`^(?:\|\s*(?:ansible\.builtin\.)?to_(?:nice_)?json\s*(?:\(\s*indent\s*=\s*\d+\s*\))?\s*)?-?\}\}$`)
)

// jsonChain reads a copy's content as the chain above. ok is false when it
// isn't one, so the copy converts, or not, as any other; a reason is why a
// chain that is one can't convert.
func jsonChain(content string) (reg string, edits []jsonEdit, ok bool, reason string) {
	content = strings.TrimSpace(content)
	m := jsonChainHead.FindStringSubmatchIndex(content)
	if m == nil {
		return "", nil, false, ""
	}
	reg, rest := content[m[2]:m[3]], content[m[1]:]
	for {
		call := jsonPatchCall.FindStringIndex(rest)
		if call == nil {
			break
		}
		ok = true
		p := &jinjaLit{s: rest[call[1]:]}
		args, why := p.args()
		if why != "" {
			return reg, nil, true, "patches the JSON with " + why
		}
		e, why := jsonPatchEdit(args)
		if why != "" {
			return reg, nil, true, why
		}
		edits = append(edits, e)
		rest = strings.TrimSpace(p.s)
	}
	if !ok {
		return "", nil, false, ""
	}
	if !jsonChainTail.MatchString(rest) {
		return reg, nil, true, "runs the patched JSON through more than to_json or to_nice_json, which json_value can't do"
	}
	return reg, edits, true, ""
}

// jsonPatchEdit is one json_patch('op', '/path', value) call as a step.
func jsonPatchEdit(args []cty.Value) (jsonEdit, string) {
	if len(args) < 2 || args[0].Type() != cty.String || args[1].Type() != cty.String {
		return jsonEdit{}, "calls json_patch with arguments other than an operation, a path and a value"
	}
	op, ptr := args[0].AsString(), args[1].AsString()
	switch op {
	case "add", "replace":
		if len(args) != 3 {
			return jsonEdit{}, fmt.Sprintf("calls json_patch(%q) without a value", op)
		}
	case "remove":
		if len(args) != 2 {
			return jsonEdit{}, "calls json_patch('remove') with a value, which Ansible ignores; take it out"
		}
	default:
		return jsonEdit{}, fmt.Sprintf("uses the json_patch %q operation; json_value sets or removes one key, so only add, replace and remove convert", op)
	}
	key, why := jsonPointerKey(ptr, op == "add")
	if why != "" {
		return jsonEdit{}, why
	}
	if op == "remove" {
		return jsonEdit{key: key, remove: true}, ""
	}
	return jsonEdit{key: key, value: args[2]}, ""
}

var jsonKeyWord = regexp.MustCompile(`^[^.\[\]]+$`)

// jsonPointerKey turns a JSON Pointer such as /upstreams/0/host into a
// json_value key, upstreams[0].host. An add at an array index inserts
// there, moving what follows, which json_value doesn't do.
func jsonPointerKey(ptr string, add bool) (string, string) {
	if !strings.HasPrefix(ptr, "/") || ptr == "/" {
		return "", fmt.Sprintf("patches the path %q, which isn't a key in the document; json_value sets one key", ptr)
	}
	parts := strings.Split(ptr[1:], "/")
	var key strings.Builder
	for i, part := range parts {
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		last := i == len(parts)-1
		switch n, err := strconv.Atoi(part); {
		case part == "-":
			return "", fmt.Sprintf("appends to an array at %q; json_value can't append yet", ptr)
		case err == nil && n >= 0 && part == strconv.Itoa(n):
			if i == 0 {
				return "", fmt.Sprintf("patches %q in a document that's an array; json_value needs an object at the top", ptr)
			}
			if add && last {
				return "", fmt.Sprintf("adds at array index %s in %q, which inserts and moves what follows; json_value replaces an element in place", part, ptr)
			}
			// shortcut: a digits-only object key reads as an array index; tell them apart once the converter reads the file.
			fmt.Fprintf(&key, "[%d]", n)
		case !jsonKeyWord.MatchString(part):
			return "", fmt.Sprintf("patches the key %q, whose name has a dot or a bracket json_value can't name", part)
		default:
			if key.Len() > 0 {
				key.WriteByte('.')
			}
			key.WriteString(part)
		}
	}
	return key.String(), ""
}

// jsonPairs finds each slurp that only feeds the json_patch chain of the
// copy right after it, writing back the same file.
func (c *converter) jsonPairs(tasks []taskAt) {
	c.jsonRead, c.jsonEdits, c.jsonWhy = map[*yaml.Node]string{}, map[*yaml.Node][]jsonEdit{}, map[*yaml.Node]string{}
	for i := 0; i+1 < len(tasks); i++ {
		src, reg := slurpOf(tasks[i].node)
		if src == "" {
			continue
		}
		next := mapping(tasks[i+1].node)
		mod, args := moduleOf(next)
		if mod != "copy" || scalar(args["dest"]) != src || args["content"] == nil {
			continue
		}
		chainReg, edits, ok, why := jsonChain(scalar(args["content"]))
		if !ok || chainReg != reg {
			continue
		}
		if why != "" {
			c.jsonWhy[tasks[i+1].node] = why
			continue
		}
		c.jsonRead[tasks[i].node] = src
		c.jsonEdits[tasks[i+1].node] = edits
	}
}

// slurpOf is the file a slurp task reads and the variable it registers,
// when that is all it does.
func slurpOf(node *yaml.Node) (src, reg string) {
	t := mapping(node)
	mod, args := moduleOf(t)
	if mod != "slurp" {
		return "", ""
	}
	for k := range t {
		if k != "name" && k != "register" && k != "tags" && k[strings.LastIndex(k, ".")+1:] != "slurp" {
			return "", ""
		}
	}
	for k := range args {
		if k != "src" && k != "path" {
			return "", ""
		}
	}
	src = scalar(args["src"])
	if src == "" {
		src = scalar(args["path"])
	}
	if !strings.HasPrefix(src, "/") || strings.Contains(src, "{{") {
		return "", ""
	}
	return src, scalar(t["register"])
}

// jsonValueSteps are a copy's json_patch chain as json_value steps.
func jsonValueSteps(in *input, edits []jsonEdit) ([]step, string) {
	path := in.str("dest")
	in.ignore("content")
	var steps []step
	for _, e := range edits {
		attrs := []attr{s("path", path), s("key", e.key)}
		if e.remove {
			attrs = append(attrs, s("state", "absent"))
		} else {
			attrs = append(attrs, attr{key: "value", raw: "jsonencode(" + strings.TrimSpace(string(hclwrite.TokensForValue(e.value).Bytes())) + ")"})
		}
		steps = append(steps, step{module: "json_value", attrs: attrs, suffix: e.key})
	}
	steps[0].notes = []string{"Was a slurp of " + path + " and a copy that ran it through json_patch; each operation is a json_value step, which leaves the rest of the file as it is written."}
	return steps, ""
}

// jinjaLit reads Jinja literals: the arguments of a filter call.
type jinjaLit struct{ s string }

func (p *jinjaLit) skip() { p.s = strings.TrimLeft(p.s, " \t\r\n") }

// args reads literals separated by commas up to the closing parenthesis.
func (p *jinjaLit) args() ([]cty.Value, string) {
	var out []cty.Value
	for {
		p.skip()
		if strings.HasPrefix(p.s, ")") {
			p.s = p.s[1:]
			return out, ""
		}
		if len(out) > 0 {
			if !strings.HasPrefix(p.s, ",") {
				return nil, "arguments the converter can't read"
			}
			p.s = p.s[1:]
			p.skip()
		}
		if jinjaKeyword.MatchString(p.s) {
			return nil, "keyword arguments, such as from= for move and copy, which json_value can't do"
		}
		v, why := p.value()
		if why != "" {
			return nil, why
		}
		out = append(out, v)
	}
}

var jinjaKeyword = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\s*=[^=]`)

var jinjaNumber = regexp.MustCompile(`^-?\d+(\.\d+)?([eE][-+]?\d+)?`)

func (p *jinjaLit) value() (cty.Value, string) {
	p.skip()
	if p.s == "" {
		return cty.NilVal, "arguments the converter can't read"
	}
	switch c := p.s[0]; c {
	case '\'', '"':
		end := strings.IndexByte(p.s[1:], c)
		if end < 0 {
			return cty.NilVal, "an unclosed string"
		}
		str := p.s[1 : end+1]
		if strings.Contains(str, `\`) {
			return cty.NilVal, "a string with a backslash escape, which the converter doesn't read yet"
		}
		p.s = p.s[end+2:]
		return cty.StringVal(str), ""
	case '[':
		p.s = p.s[1:]
		var elems []cty.Value
		for {
			p.skip()
			if strings.HasPrefix(p.s, "]") {
				p.s = p.s[1:]
				if len(elems) == 0 {
					return cty.EmptyTupleVal, ""
				}
				return cty.TupleVal(elems), ""
			}
			if len(elems) > 0 {
				if !strings.HasPrefix(p.s, ",") {
					return cty.NilVal, "a list the converter can't read"
				}
				p.s = p.s[1:]
				p.skip()
				if strings.HasPrefix(p.s, "]") {
					continue // a trailing comma
				}
			}
			v, why := p.value()
			if why != "" {
				return cty.NilVal, why
			}
			elems = append(elems, v)
		}
	case '{':
		p.s = p.s[1:]
		obj := map[string]cty.Value{}
		var order []string
		for {
			p.skip()
			if strings.HasPrefix(p.s, "}") {
				p.s = p.s[1:]
				if len(order) == 0 {
					return cty.EmptyObjectVal, ""
				}
				return cty.ObjectVal(obj), ""
			}
			if len(order) > 0 {
				if !strings.HasPrefix(p.s, ",") {
					return cty.NilVal, "a dictionary the converter can't read"
				}
				p.s = p.s[1:]
				p.skip()
				if strings.HasPrefix(p.s, "}") {
					continue
				}
			}
			k, why := p.value()
			if why != "" {
				return cty.NilVal, why
			}
			if k.Type() != cty.String {
				return cty.NilVal, "a dictionary key that isn't a string"
			}
			p.skip()
			if !strings.HasPrefix(p.s, ":") {
				return cty.NilVal, "a dictionary the converter can't read"
			}
			p.s = p.s[1:]
			v, why := p.value()
			if why != "" {
				return cty.NilVal, why
			}
			if _, dup := obj[k.AsString()]; !dup {
				order = append(order, k.AsString())
			}
			obj[k.AsString()] = v
		}
	}
	if n := jinjaNumber.FindString(p.s); n != "" {
		f, _, err := big.ParseFloat(n, 10, 512, big.ToNearestEven)
		if err != nil {
			return cty.NilVal, "a number the converter can't read"
		}
		p.s = p.s[len(n):]
		return cty.NumberVal(f), ""
	}
	word := p.s
	if i := strings.IndexAny(word, " \t\r\n,)]}:"); i >= 0 {
		word = word[:i]
	}
	p.s = p.s[len(word):]
	switch word {
	case "true", "True":
		return cty.True, ""
	case "false", "False":
		return cty.False, ""
	case "none", "None", "null":
		return cty.NullVal(cty.DynamicPseudoType), ""
	}
	return cty.NilVal, fmt.Sprintf("the value %q, a variable or expression rather than a literal; set it by hand", word)
}
