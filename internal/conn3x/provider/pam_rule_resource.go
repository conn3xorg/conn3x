// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/pam"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

const pamDir = "/etc/pam.d"

// pamRuleKind is one rule in a PAM service file, edited like any other
// part of a file, so it writes the way line and limit do.
var pamRuleKind = editKind{
	name: "pam_rule",
	desc: "One rule in a PAM service file, such as auth required pam_faillock.so in /etc/pam.d/sshd, found by its type, control and module. Comments, @include lines and the other rules stay as they are.",
	attrs: map[string]*configschema.Attribute{
		"service":   {Type: cty.String, Required: true, Description: "The service file's name, such as \"sshd\" or \"common-auth\"."},
		"path":      {Type: cty.String, Optional: true, Description: "The directory the service file is in. Defaults to \"/etc/pam.d\"."},
		"type":      {Type: cty.String, Required: true, Description: "\"account\", \"auth\", \"password\" or \"session\", or one of those after a -, such as \"-session\", which PAM skips when the module isn't installed."},
		"control":   {Type: cty.String, Required: true, Description: "\"required\", \"requisite\", \"sufficient\", \"optional\", \"include\" or \"substack\", or value=action pairs in brackets, such as \"[success=1 default=ignore]\"."},
		"module":    {Type: cty.String, Required: true, Description: "The module, such as \"pam_faillock.so\", as the file names it."},
		"arguments": {Type: cty.List(cty.String), Optional: true, Description: "With state \"present\", the rule's arguments, all of them; unset leaves a rule that's there with the arguments it has. With \"args_present\" or \"args_absent\", the arguments to add or take out. An argument with spaces goes in brackets, such as \"[query=select 1]\"."},
		"state":     {Type: cty.String, Optional: true, Description: "\"present\" (default) keeps the rule, \"absent\" takes out every rule that matches, \"args_present\" adds arguments to it, where a key=value takes the place of one with the same key, and \"args_absent\" takes arguments out."},
		"before":    {Type: cty.String, Optional: true, Description: "Where the rule goes when it isn't there: before this rule, given as \"type control module\", such as \"auth sufficient pam_unix.so\". It must be in the file once."},
		"after":     {Type: cty.String, Optional: true, Description: "Where the rule goes when it isn't there: after this rule, given as \"type control module\". It must be in the file once."},
		"replace":   {Type: cty.String, Optional: true, Description: "A rule, given as \"type control module\", to turn into this one in place, keeping its arguments unless arguments is set."},
	},
	file: func(v cty.Value) string {
		return path.Join(stringOr(v.GetAttr("path"), pamDir), stringOr(v.GetAttr("service"), ""))
	},
	edit: func(v cty.Value) func(string) (string, error) {
		r := pamRuleFrom(v)
		return func(s string) (string, error) { return pam.Apply(s, r) }
	},
	remove: func(v cty.Value) func(string) (string, error) {
		r := pamRuleFrom(v)
		switch r.State {
		case pam.Present:
			r = pam.Rule{Ref: r.Ref, State: pam.Absent}
		case pam.ArgsPresent:
			r.State = pam.ArgsAbsent
		default:
			return func(s string) (string, error) { return s, nil }
		}
		return func(s string) (string, error) { return pam.Apply(s, r) }
	},
	check: func(v cty.Value) error {
		svc := stringOr(v.GetAttr("service"), "")
		if svc == "" || svc == "." || svc == ".." || strings.ContainsAny(svc, "/ \t\r\n\x00") {
			return fmt.Errorf("service %q must be a file name in path, such as \"sshd\"", svc)
		}
		r := pamRuleFrom(v)
		if v.GetAttr("on_remove").RawEquals(cty.StringVal(onRemoveDelete)) && r.State != pam.Present && r.State != pam.ArgsPresent {
			return fmt.Errorf(`on_remove can't be "delete" with state %q: what it took out can't be put back`, r.State)
		}
		return r.Validate()
	},
	missingOK: func(v cty.Value) bool {
		st := pamRuleFrom(v).State
		return st == pam.Absent || st == pam.ArgsAbsent
	},
	hostCheck: refuseAuthselectFile,
}

func pamRuleFrom(v cty.Value) pam.Rule {
	r := pam.Rule{
		Ref:     pam.Ref{Type: stringOr(v.GetAttr("type"), ""), Control: stringOr(v.GetAttr("control"), ""), Module: stringOr(v.GetAttr("module"), "")},
		State:   pam.State(stringOr(v.GetAttr("state"), string(pam.Present))),
		Before:  stringOr(v.GetAttr("before"), ""),
		After:   stringOr(v.GetAttr("after"), ""),
		Replace: stringOr(v.GetAttr("replace"), ""),
	}
	if a := v.GetAttr("arguments"); known(a) {
		r.Arguments = append([]string{}, stringList(a)...) // set but empty is no arguments, not unset
	}
	return r
}

// authselectFiles are the PAM files authselect writes on RHEL-family
// hosts, as links into /etc/authselect.
var authselectFiles = []string{"system-auth", "password-auth", "postlogin", "smartcard-auth", "fingerprint-auth", "switchable-auth"}

// refuseAuthselectFile fails on a file authselect manages: it writes the
// file again on its next run and drops whatever a step changed.
func refuseAuthselectFile(ctx context.Context, h *hostConn, file string) error {
	q := ssh.Quote(file)
	res, err := h.Run(ctx, `test -e /etc/authselect/authselect.conf || exit 0
case "$(readlink -f -- `+q+` 2>/dev/null)" in /etc/authselect/*) exit 3;; esac
exit 4`, nil)
	if err != nil {
		return err
	}
	return authselectRefusal(file, res.ExitCode, string(res.Stderr))
}

// authselectRefusal reads the check's exit code: 0 for no authselect, 3
// for a link into /etc/authselect, 4 for any other file.
func authselectRefusal(file string, code int, stderr string) error {
	switch {
	case code == 0, code == 4 && !slices.Contains(authselectFiles, path.Base(file)):
		return nil
	case code == 3, code == 4:
		return errors.New(file + ` is managed by authselect, which writes it again on its next "authselect apply-changes" or "authselect select" and drops what this step changed. ` +
			`Make the change through authselect instead, with a feature such as "authselect enable-feature with-faillock", or a custom profile made with "authselect create-profile". ` +
			`If this host shouldn't use authselect, run "authselect opt-out" first.`)
	}
	return fmt.Errorf("checking whether authselect manages %s: exit %d: %s", file, code, strings.TrimSpace(stderr))
}
