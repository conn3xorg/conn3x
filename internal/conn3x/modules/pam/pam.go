// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package pam edits one rule in a PAM service file, such as
// /etc/pam.d/sshd, and leaves every other line as it was: comments, blank
// lines, @include lines and the other rules' own spacing.
//
// A rule is found the way community.general.pamd finds one, by its type,
// control and module. The file is read as Linux-PAM reads it: a # starts a
// comment anywhere on a line, and a line ending in a backslash goes on to
// the next one, unless it has a comment.
package pam

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// State is what a Rule does to the rules it matches.
type State string

const (
	Present     State = "present"      // the rule is there, with Arguments when they're set
	Absent      State = "absent"       // no rule matches
	ArgsPresent State = "args_present" // each matching rule has these arguments
	ArgsAbsent  State = "args_absent"  // no matching rule has these arguments
)

// Ref names a rule by its type, control and module, such as
// auth [success=1 default=ignore] pam_unix.so.
type Ref struct{ Type, Control, Module string }

func (r Ref) String() string { return r.Type + " " + r.Control + " " + r.Module }

// matches reports whether a rule in a file is r. The type and module
// must be the same; a bracketed control may be spaced differently.
func (r Ref) matches(o Ref) bool {
	return r.Type == o.Type && r.Module == o.Module && NormalControl(r.Control) == NormalControl(o.Control)
}

var aroundEquals = regexp.MustCompile(`\s*=\s*`)

// NormalControl is a control with a bracketed one's spacing made plain,
// as Linux-PAM allows spaces around = and between pairs.
func NormalControl(c string) string {
	if !strings.HasPrefix(c, "[") || !strings.HasSuffix(c, "]") {
		return c
	}
	inner := aroundEquals.ReplaceAllString(c[1:len(c)-1], "=")
	return "[" + strings.Join(strings.Fields(inner), " ") + "]"
}

// ParseRef reads "type control module", the form before, after and
// replace take.
func ParseRef(s string) (Ref, error) {
	toks, err := tokens(s)
	if err != nil {
		return Ref{}, err
	}
	if len(toks) != 3 {
		return Ref{}, fmt.Errorf("%q should be a type, a control and a module, such as \"auth sufficient pam_unix.so\"", s)
	}
	r := Ref{toks[0].text, toks[1].text, toks[2].text}
	return r, r.validate()
}

var (
	types          = []string{"account", "auth", "password", "session"}
	simpleControls = []string{"required", "requisite", "sufficient", "optional", "include", "substack"}
	// The return values and actions a bracketed control takes, from
	// Linux-PAM's pam_tokens.h.
	controlValues = []string{"success", "open_err", "symbol_err", "service_err", "system_err", "buf_err", "perm_denied",
		"auth_err", "cred_insufficient", "authinfo_unavail", "user_unknown", "maxtries", "new_authtok_reqd", "acct_expired",
		"session_err", "cred_unavail", "cred_expired", "cred_err", "no_module_data", "conv_err", "authtok_err",
		"authtok_recover_err", "authtok_lock_busy", "authtok_disable_aging", "try_again", "ignore", "abort",
		"authtok_expired", "module_unknown", "bad_item", "conv_again", "incomplete", "default"}
	controlActions = []string{"ignore", "ok", "done", "bad", "die", "reset"}
)

// validate checks a Ref the step writes. Linux-PAM makes a stack with a
// rule it can't read fail every time, so a typo here would lock people out.
func (r Ref) validate() error {
	if !slices.Contains(types, strings.TrimPrefix(r.Type, "-")) {
		return fmt.Errorf("type %q must be account, auth, password or session, or one of those after a - to skip a module that isn't installed", r.Type)
	}
	if err := validControl(r.Control); err != nil {
		return err
	}
	if r.Module == "" || strings.ContainsAny(r.Module, " \t\r\n#[]\\\x00") {
		return fmt.Errorf("module %q must be a module such as pam_unix.so, or a path to one, with no spaces", r.Module)
	}
	return nil
}

func validControl(c string) error {
	if slices.Contains(simpleControls, c) {
		return nil
	}
	if !strings.HasPrefix(c, "[") || !strings.HasSuffix(c, "]") || strings.ContainsAny(c[1:len(c)-1], "[]#\\\r\n\x00") {
		return fmt.Errorf("control %q must be one of %s, or value=action pairs in brackets, such as [success=1 default=ignore]", c, strings.Join(simpleControls, ", "))
	}
	pairs := strings.Fields(NormalControl(c)[1 : len(NormalControl(c))-1])
	if len(pairs) == 0 {
		return fmt.Errorf("control %q has nothing in its brackets", c)
	}
	for _, p := range pairs {
		v, a, ok := strings.Cut(p, "=")
		if !ok || !slices.Contains(controlValues, v) {
			return fmt.Errorf("control %q: %q should be value=action, with a value such as success, default or user_unknown", c, p)
		}
		if n, err := strconv.Atoi(a); !slices.Contains(controlActions, a) && (err != nil || n < 1 || strconv.Itoa(n) != a) {
			return fmt.Errorf("control %q: %q should end in ignore, ok, done, bad, die, reset or a jump of 1 or more", c, p)
		}
	}
	return nil
}

// Rule is what a step wants of the rules matching Ref.
type Rule struct {
	Ref
	// Arguments are the rule's arguments, all of them with Present, or the
	// ones to add or take out with ArgsPresent and ArgsAbsent. Nil with
	// Present leaves a rule's arguments as they are.
	Arguments []string
	State     State
	// Before or After places a rule Present adds, next to the one rule
	// they name. Replace names a rule to change into this one, in place.
	Before, After, Replace string
}

// Validate checks a Rule before anything reaches the host.
func (r Rule) Validate() error {
	if err := r.validate(); err != nil {
		return err
	}
	switch r.State {
	case Present, Absent, ArgsPresent, ArgsAbsent:
	default:
		return fmt.Errorf(`state must be "present", "absent", "args_present" or "args_absent", not %q`, r.State)
	}
	for _, a := range r.Arguments {
		if err := validArg(a); err != nil {
			return err
		}
	}
	if r.State != Present && (r.Before != "" || r.After != "" || r.Replace != "") {
		return errors.New(`before, after and replace only go with state "present"`)
	}
	if r.Before != "" && r.After != "" {
		return errors.New("set before or after, not both")
	}
	for what, s := range map[string]string{"before": r.Before, "after": r.After, "replace": r.Replace} {
		if s == "" {
			continue
		}
		ref, err := ParseRef(s)
		if err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
		if ref.matches(r.Ref) {
			return fmt.Errorf("%s names this rule itself", what)
		}
	}
	switch r.State {
	case Absent:
		if r.Arguments != nil {
			return errors.New(`arguments don't go with state "absent": every matching rule goes, whatever its arguments`)
		}
	case ArgsPresent, ArgsAbsent:
		if len(r.Arguments) == 0 {
			return fmt.Errorf("state %q needs arguments", r.State)
		}
		if r.State == ArgsPresent && slices.ContainsFunc(r.Arguments, func(a string) bool { return strings.HasPrefix(a, "[") }) {
			return errors.New(`a bracketed argument can't be added with "args_present"; set the rule's arguments whole with state "present"`)
		}
	}
	return nil
}

// validArg checks one argument: a word, or text in brackets, which may
// have spaces in it. A # would comment out the rest of the line, and a
// trailing backslash would join the next line onto it.
func validArg(a string) error {
	toks, err := tokens(a)
	switch {
	case a == "" || strings.ContainsAny(a, "#\r\n\x00") || strings.HasSuffix(a, `\`):
		return fmt.Errorf("argument %q can't be empty, or hold a #, a line break or a trailing backslash", a)
	case err != nil || len(toks) != 1 || toks[0].text != a:
		return fmt.Errorf("argument %q would be read as more than one; put an argument with spaces in brackets, such as [query=select 1]", a)
	}
	return nil
}

// token is one word of a rule, with where it starts and ends.
type token struct {
	text       string
	start, end int
}

// tokens splits a rule as Linux-PAM does: at spaces and tabs, except
// inside [...], where \] is a ] that doesn't end it.
func tokens(s string) ([]token, error) {
	var out []token
	for i := 0; ; {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n') {
			i++
		}
		if i == len(s) {
			return out, nil
		}
		start := i
		if s[i] == '[' {
			for i++; i < len(s) && s[i] != ']'; i++ {
				if s[i] == '\\' && i+1 < len(s) && s[i+1] == ']' {
					i++
				}
			}
			if i == len(s) {
				return nil, fmt.Errorf("%q has a [ with no ] to close it", s)
			}
		}
		for i < len(s) && s[i] != ' ' && s[i] != '\t' && s[i] != '\n' {
			i++
		}
		out = append(out, token{s[start:i], start, i})
	}
}

// entry is one line of a file, or several joined by backslashes. rule is
// nil for a comment, a blank line or an @include.
type entry struct {
	text string
	rule *rule
}

type rule struct {
	Ref
	args []string
	// head is the rule up to the end of its module, as written; sep1 and
	// sep2 are the spaces between its type, control and module.
	head, sep1, sep2 string
	comment          string // from the # on, if any
	edited           bool
}

func (r *rule) render() string {
	s := r.head
	if len(r.args) > 0 {
		s += " " + strings.Join(r.args, " ")
	}
	if r.comment != "" {
		s += " " + r.comment
	}
	return s
}

// relabel gives r another type, control and module, keeping its indent
// and the columns its parts start at.
func (r *rule) relabel(ref Ref) {
	indent := r.head[:len(r.head)-len(strings.TrimLeft(r.head, " \t"))]
	r.head = indent + ref.Type + pad(r.sep1, r.Type, ref.Type) + ref.Control + pad(r.sep2, r.Control, ref.Control) + ref.Module
	r.Ref, r.edited = ref, true
}

// pad is the space after was, before the next part, made to keep that
// part in its column when is takes was's place. Tabs are kept as they are.
func pad(sep, was, is string) string {
	if strings.Contains(sep, "\t") {
		return sep
	}
	return strings.Repeat(" ", max(1, len(was)+len(sep)-len(is)))
}

// parse reads content into entries, and whether it ended in a newline.
func parse(content string) ([]entry, bool, error) {
	if content == "" {
		return nil, true, nil
	}
	final := strings.HasSuffix(content, "\n")
	lines := strings.Split(strings.TrimSuffix(content, "\n"), "\n")
	var out []entry
	for i := 0; i < len(lines); i++ {
		start, logical := i, ""
		for {
			l := lines[i]
			t := strings.TrimRight(l, " \t")
			if !strings.Contains(l, "#") && strings.HasSuffix(t, `\`) {
				logical += strings.TrimSuffix(t, `\`) + " "
				if i+1 < len(lines) {
					i++
					continue
				}
				break
			}
			logical += l
			break
		}
		text := strings.Join(lines[start:i+1], "\n")
		body, comment := logical, ""
		if j := strings.Index(logical, "#"); j >= 0 {
			body, comment = logical[:j], logical[j:]
		}
		body = strings.TrimRight(body, " \t")
		trimmed := strings.TrimSpace(body)
		if trimmed == "" || strings.HasPrefix(trimmed, "@include") {
			out = append(out, entry{text: text})
			continue
		}
		toks, err := tokens(body)
		if err != nil {
			return nil, false, fmt.Errorf("line %d: %w", start+1, err)
		}
		if len(toks) < 3 {
			return nil, false, fmt.Errorf("line %d isn't a PAM rule, which has a type, a control and a module: %q", start+1, text)
		}
		if !slices.Contains(types, strings.ToLower(strings.TrimPrefix(toks[0].text, "-"))) {
			return nil, false, fmt.Errorf("line %d has type %q, which PAM doesn't know: %q", start+1, toks[0].text, text)
		}
		r := &rule{
			Ref:     Ref{toks[0].text, toks[1].text, toks[2].text},
			head:    body[:toks[2].end],
			sep1:    body[toks[0].end:toks[1].start],
			sep2:    body[toks[1].end:toks[2].start],
			comment: comment,
		}
		for _, t := range toks[3:] {
			r.args = append(r.args, t.text)
		}
		out = append(out, entry{text: text, rule: r})
	}
	return out, final, nil
}

func render(es []entry, final bool) string {
	var b strings.Builder
	for i, e := range es {
		if i > 0 {
			b.WriteByte('\n')
		}
		if e.rule != nil && e.rule.edited {
			b.WriteString(e.rule.render())
		} else {
			b.WriteString(e.text)
		}
	}
	if final && len(es) > 0 {
		b.WriteByte('\n')
	}
	return b.String()
}

// authRules counts the auth rules, which are what let anyone log in.
// A -auth rule doesn't count: PAM skips it when its module is missing.
func authRules(es []entry) int {
	n := 0
	for _, e := range es {
		if e.rule != nil && strings.EqualFold(e.rule.Type, "auth") {
			n++
		}
	}
	return n
}

// Apply returns content with r applied, or content itself when it
// already matches. It refuses to take out a file's last auth rule.
func Apply(content string, r Rule) (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	es, final, err := parse(content)
	if err != nil {
		return "", err
	}
	authBefore := authRules(es)
	var matched []*rule
	for _, e := range es {
		if e.rule != nil && r.matches(e.rule.Ref) {
			matched = append(matched, e.rule)
		}
	}
	changed := false
	setArgs := func(m *rule, args []string) {
		if !slices.Equal(m.args, args) {
			m.args, m.edited, changed = args, true, true
		}
	}
	switch r.State {
	case Absent:
		es = slices.DeleteFunc(es, func(e entry) bool { return e.rule != nil && slices.Contains(matched, e.rule) })
		changed = len(matched) > 0
	case ArgsAbsent:
		for _, m := range matched {
			setArgs(m, slices.DeleteFunc(slices.Clone(m.args), func(a string) bool { return slices.Contains(r.Arguments, a) }))
		}
	case ArgsPresent:
		if len(matched) == 0 {
			return "", fmt.Errorf("there's no %s rule to add arguments to", r.Ref)
		}
		for _, m := range matched {
			setArgs(m, withArgs(m.args, r.Arguments))
		}
	case Present:
		if r.Replace != "" {
			old, _ := ParseRef(r.Replace)
			for _, e := range es {
				if e.rule != nil && old.matches(e.rule.Ref) {
					e.rule.relabel(r.Ref)
					matched, changed = append(matched, e.rule), true
				}
			}
		}
		if len(matched) == 0 {
			n, err := r.insert(&es)
			if err != nil {
				return "", err
			}
			matched, changed = []*rule{n}, true
		}
		if r.Arguments != nil {
			for _, m := range matched {
				setArgs(m, r.Arguments)
			}
		}
	}
	if !changed {
		return content, nil
	}
	if authBefore > 0 && authRules(es) == 0 {
		return "", errors.New("that would take out the last auth rule, and nobody could log in through this service; add the rule that replaces it first")
	}
	out := render(es, final)
	if _, _, err := parse(out); err != nil {
		return "", fmt.Errorf("the edited file wouldn't read back as PAM rules, so it's left alone: %w", err)
	}
	return out, nil
}

// insert puts a new rule for r before or after its anchor, which must
// name exactly one rule in the file.
func (r Rule) insert(es *[]entry) (*rule, error) {
	where, anchor := "before", r.Before
	if r.After != "" {
		where, anchor = "after", r.After
	}
	if anchor == "" {
		if r.Replace != "" {
			return nil, fmt.Errorf("neither %s nor %s is in the file", r.Ref, r.Replace)
		}
		return nil, fmt.Errorf("%s isn't in the file; set before or after to say where it goes", r.Ref)
	}
	ref, _ := ParseRef(anchor)
	at := -1
	for i, e := range *es {
		if e.rule != nil && ref.matches(e.rule.Ref) {
			if at >= 0 {
				return nil, fmt.Errorf("%s matches more than one rule, so it doesn't say where %s goes; name a rule that's there once", anchor, r.Ref)
			}
			at = i
		}
	}
	if at < 0 {
		return nil, fmt.Errorf("%s isn't in the file, so there's nowhere to put %s %s it", anchor, r.Ref, where)
	}
	a := (*es)[at].rule
	n := &rule{Ref: a.Ref, head: a.head, sep1: a.sep1, sep2: a.sep2}
	n.relabel(r.Ref)
	if r.After != "" {
		at++
	}
	*es = slices.Insert(*es, at, entry{rule: n})
	return n, nil
}

// withArgs is args with each of add in it: a key=value takes the place of
// the first argument with that key, and anything else missing goes on the
// end, in order.
func withArgs(args, add []string) []string {
	out := slices.Clone(args)
	for _, a := range add {
		key, _, kv := strings.Cut(a, "=")
		i := slices.IndexFunc(out, func(o string) bool {
			k, _, ok := strings.Cut(o, "=")
			return o == a || kv && ok && k == key
		})
		if i < 0 {
			out = append(out, a)
		} else {
			out[i] = a
		}
	}
	return out
}
