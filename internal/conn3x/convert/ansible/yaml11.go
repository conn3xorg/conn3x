// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Ansible reads playbooks with PyYAML, which follows YAML 1.1: an unquoted
// yes is True, 1.10 is 1.1 and 0755 is 493. yaml.v3 hands the converter
// the text as written. These are PyYAML 6.0.2's implicit resolvers, from
// https://github.com/yaml/pyyaml/blob/6.0.2/lib/yaml/resolver.py, which
// Ansible's loader uses unchanged.
var (
	yaml11Bool  = regexp.MustCompile(`^(?:yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF)$`)
	yaml11Float = regexp.MustCompile(`^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$`)
	yaml11Int   = regexp.MustCompile(`^(?:[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)$`)
	yaml11Null  = regexp.MustCompile(`^(?:~|null|Null|NULL|)$`)
)

// yaml11Scalar is what PyYAML makes of the unquoted plain scalar s: its
// type, or "" for a string, and Python's str() of the value, which is the
// text a module or an environment variable gets. The values follow
// PyYAML's constructors in lib/yaml/constructor.py.
//
// shortcut: timestamps aren't covered; str() of a date alone is its text,
// but one with a time isn't, so add them if a playbook needs it.
func yaml11Scalar(s string) (kind, passed string) {
	switch {
	case yaml11Bool.MatchString(s):
		if strings.Contains("yYtToO", s[:1]) && !strings.EqualFold(s, "off") {
			return "bool", "True"
		}
		return "bool", "False"
	case yaml11Int.MatchString(s):
		return "int", yaml11Int64(s)
	case yaml11Float.MatchString(s):
		return "float", yaml11Float64(s)
	case yaml11Null.MatchString(s):
		return "null", "None"
	}
	return "", s
}

// yaml11Int64 is construct_yaml_int, written as a decimal.
func yaml11Int64(s string) string {
	v, sign := strings.ReplaceAll(s, "_", ""), ""
	if v[0] == '-' || v[0] == '+' {
		sign, v = strings.TrimPrefix(v[:1], "+"), v[1:]
	}
	var n int64
	switch {
	case v == "0":
	case strings.HasPrefix(v, "0b"):
		n, _ = strconv.ParseInt(v[2:], 2, 64)
	case strings.HasPrefix(v, "0x"):
		n, _ = strconv.ParseInt(v[2:], 16, 64)
	case v[0] == '0':
		n, _ = strconv.ParseInt(v, 8, 64)
	case strings.Contains(v, ":"):
		for _, d := range strings.Split(v, ":") {
			p, _ := strconv.ParseInt(d, 10, 64)
			n = n*60 + p
		}
	default:
		n, _ = strconv.ParseInt(v, 10, 64)
	}
	if n == 0 {
		sign = ""
	}
	return sign + strconv.FormatInt(n, 10)
}

// yaml11Float64 is construct_yaml_float, written as Python's repr.
func yaml11Float64(s string) string {
	v, sign := strings.ToLower(strings.ReplaceAll(s, "_", "")), 1.0
	if v[0] == '-' || v[0] == '+' {
		if v[0] == '-' {
			sign = -1
		}
		v = v[1:]
	}
	var f float64
	switch {
	case v == ".inf":
		f = math.Inf(1)
	case v == ".nan":
		return "nan"
	case strings.Contains(v, ":"):
		for _, d := range strings.Split(v, ":") {
			p, _ := strconv.ParseFloat(d, 64)
			f = f*60 + p
		}
	default:
		f, _ = strconv.ParseFloat(v, 64)
	}
	return pythonFloat(sign * f)
}

// pythonFloat is Python's repr of f: the shortest digits that read back,
// in exponent form below 1e-4 and from 1e16, and with .0 on a whole number.
func pythonFloat(f float64) string {
	switch {
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	}
	e := strconv.FormatFloat(f, 'e', -1, 64)
	exp, _ := strconv.Atoi(e[strings.IndexByte(e, 'e')+1:])
	if f != 0 && (exp < -4 || exp >= 16) {
		return e
	}
	out := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.Contains(out, ".") {
		out += ".0"
	}
	return out
}

// yaml11Retyped says why n, read as text, isn't the text Ansible gets: an
// unquoted plain scalar that PyYAML reads as something whose str() differs,
// such as yes, 1.10 or 0755. "" when n is what Ansible passes. A node with
// no tag wasn't parsed from YAML, such as a value in key=value text, which
// Ansible doesn't retype either.
func yaml11Retyped(key string, n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode || n.Style != 0 || n.Tag == "" {
		return ""
	}
	kind, passed := yaml11Scalar(n.Value)
	if kind == "" || passed == n.Value {
		return ""
	}
	return fmt.Sprintf("%s is the unquoted YAML 1.1 %s %q, which Ansible passes as %q; quote it to keep the text", key, kind, n.Value, passed)
}

// freeText lists, by module, the arguments that take any text, where a
// value Ansible's YAML 1.1 retypes reaches the host as other text. Typed
// arguments, such as a mode or a boolean, are read by their own rules.
var freeText = map[string][]string{
	"copy":            {"content"},
	"win_copy":        {"content"},
	"lineinfile":      {"line"},
	"win_lineinfile":  {"line"},
	"blockinfile":     {"block", "content"},
	"win_environment": {"value"},
	"command":         {"_raw", "cmd", "stdin"},
	"shell":           {"_raw", "cmd", "stdin"},
	"script":          {"_raw", "cmd"},
	"raw":             {"_raw"},
	"win_command":     {"_raw", "cmd", "stdin"},
	"win_shell":       {"_raw", "cmd"},
}

// checkFreeText leaves the task for review when a free-text argument, or a
// play variable written into one, is a value Ansible's YAML 1.1 retypes.
func (in *input) checkFreeText() {
	for _, k := range freeText[in.mod] {
		n := in.args[k]
		if n == nil {
			continue
		}
		if why := yaml11Retyped(k, n); why != "" {
			in.fail(why)
			return
		}
		for _, m := range jinja.FindAllStringSubmatch(n.Value, -1) {
			if why := in.retypedVars[m[1]]; why != "" {
				in.fail(fmt.Sprintf("%s reads {{ %s }}, and %s", k, m[1], why))
				return
			}
		}
	}
}
