// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"

	"github.com/opentofu/opentofu/internal/command"
	"github.com/opentofu/opentofu/internal/configs"
	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/importid"
	"github.com/opentofu/opentofu/internal/conn3x/provider"
)

// maxContent is the largest file content generate prints; past it, or when
// the content isn't UTF-8, the step gets content_wo with a placeholder.
const maxContent = 64 << 10

const contentPlaceholder = "REPLACE ME"

type generateOptions struct {
	host, user, keyFile, knownHosts, name string
	port                                  int
	become, writeOnly                     bool
	module                                string
	args                                  []string
}

func generateCommand() command.Command {
	var o generateOptions
	step := command.Command{
		Name:  "step",
		Short: "Print a step for what a host already has",
		Long: `Reads one object on a host, the way a step's import does, and prints a step for it with import = true, so pasting it into a circuit and planning adopts it with nothing to change.

Name the module and the arguments that identify the object, as in:

  conn3x generate step -host 203.0.113.10 -user root file path=/etc/motd
  conn3x generate step -host 203.0.113.10 -user deploy -become service name=nginx

Values are read as HCL where they parse, such as uid=1000 or groups=["ops"], and as strings otherwise.

A file's content is printed as it is, unless it isn't UTF-8 or is over 64 KiB: then the step gets content_wo with a placeholder for you to fill in. With -write-only it always does, and the content never leaves the host.

The modules a step can import can be generated. For those whose reads only say whether the host matches, such as cron, sysctl and the firewall rules, the step holds the arguments you give, once the host is shown to have the object.

The host is checked against known_hosts (~/.ssh/known_hosts unless -known-hosts-file says otherwise), as a plan checks it. Exits 0 when it printed a step and 1 on errors, including when the host doesn't have the object.`,
	}
	step.CommandLine.PositionalArg(&o.module, "MODULE", true)
	step.CommandLine.VariadicArg(&o.args, "NAME=VALUE")
	step.UsageOverride.Usage = "conn3x [global options] generate step -host <HOST> [options] <MODULE> [NAME=VALUE ...]"
	step.CommandLine.StringVar(&o.host, "host", "", "Host name or address to read from.")
	step.CommandLine.StringVar(&o.user, "user", "", "User to log in as.")
	step.CommandLine.IntVar(&o.port, "port", 0, "SSH port. Defaults to 22.")
	step.CommandLine.StringVar(&o.keyFile, "private-key-file", "", "Private key to log in with. Defaults to the SSH agent.")
	step.CommandLine.StringVar(&o.knownHosts, "known-hosts-file", "", "known_hosts file to check the host against. Defaults to ~/.ssh/known_hosts.")
	step.CommandLine.BoolVar(&o.become, "become", false, "Read as root through sudo, as become in a circuit's ssh block.")
	step.CommandLine.StringVar(&o.name, "name", "", "The step's name. Defaults to one made from the object, such as etc_motd.")
	step.CommandLine.BoolVar(&o.writeOnly, "write-only", false, "For a file: print content_wo with a placeholder, and keep the content on the host.")
	step.Run = func(command.Meta) int {
		return runGenerateStep(context.Background(), o, stdout, os.Stderr)
	}
	return command.Command{
		Name:     "generate",
		Short:    "Write configuration from what already exists",
		Long:     "Writes configuration from what already exists. Today that is a step from what a host already has.",
		GroupID:  command.OtherCommandGroup.ID,
		Commands: []command.Command{step},
	}
}

// generateSeeds are arguments a module's read fills in only when they're
// set, so generate sets them for the read to replace with the host's.
var generateSeeds = map[string]map[string]cty.Value{
	"file":      {"owner": cty.StringVal("root"), "group": cty.StringVal("root")},
	"directory": {"owner": cty.StringVal("root"), "group": cty.StringVal("root")},
	"service":   {"state": cty.StringVal("started"), "enabled": cty.True},
}

// generateSkip are attributes a step never sets from generate's output.
var generateSkip = map[string]bool{"id": true, "revision": true, "in_sync": true, "content_hmac": true, "validate": true, "content_wo": true, "on_remove": true}

func runGenerateStep(ctx context.Context, o generateOptions, stdout, stderr io.Writer) int {
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "Error: "+format+"\n", a...)
		return 1
	}
	if o.host == "" {
		return fail("-host is required, as in: conn3x generate step -host 203.0.113.10 -user root file path=/etc/motd")
	}
	if o.module == "" {
		return fail("name a module, as in: conn3x generate step -host %s file path=/etc/motd", o.host)
	}
	typ, ok := configs.ImportableType(o.module)
	if !ok {
		return fail("%q can't be generated: generate covers the modules a step can import", o.module)
	}
	if strings.HasPrefix(typ, "conn3x_windows_") {
		// A Windows read only says whether the host matches, so there'd be
		// nothing of the host's in the step.
		return fail("%q can't be generated: generate doesn't read Windows hosts yet. Write the step and set import on it instead", o.module)
	}
	if o.writeOnly && o.module != "file" {
		return fail("-write-only is for file steps")
	}
	p, _ := provider.New()
	block := p.GetProviderSchema(ctx).ResourceTypes[typ].Block

	given := map[string]cty.Value{}
	for _, arg := range o.args {
		name, text, ok := strings.Cut(arg, "=")
		attr := block.Attributes[name]
		switch {
		case !ok:
			return fail("%q isn't NAME=VALUE", arg)
		case attr == nil || (attr.Computed && !attr.Optional):
			return fail("%s has no argument %q", o.module, name)
		case generateSkip[name] || importid.LeftOut(name):
			return fail("%s isn't read from the host, so generate doesn't take it", name)
		}
		v, err := convert.Convert(argValue(text, attr.Type), attr.Type)
		if err != nil {
			return fail("%s: %s", name, err)
		}
		given[name] = v
	}
	args := map[string]cty.Value{}
	for name, v := range generateSeeds[o.module] {
		args[name] = v
	}
	for name, v := range given {
		args[name] = v
	}
	if o.writeOnly {
		args["content_wo"] = cty.StringVal(contentPlaceholder) // only marks the ID write-only
	}

	ssh := map[string]cty.Value{"host": cty.StringVal(o.host)}
	if o.user != "" {
		ssh["user"] = cty.StringVal(o.user)
	}
	if o.port != 0 {
		ssh["port"] = cty.NumberIntVal(int64(o.port))
	}
	if o.keyFile != "" {
		ssh["private_key_file"] = cty.StringVal(o.keyFile)
	}
	if o.knownHosts != "" {
		ssh["known_hosts_file"] = cty.StringVal(o.knownHosts)
	}
	if o.become {
		ssh["become"] = cty.True
	}
	id, err := importid.Build(o.host, cty.ObjectVal(ssh), cty.ObjectVal(args))
	if err != nil {
		return fail("%s", err)
	}
	state, err := provider.ReadExisting(ctx, typ, id)
	if err != nil {
		return fail("%s", err)
	}
	name := o.name
	if name == "" {
		name = stepName(o.module, given)
	}
	if _, err := stdout.Write(renderStep(name, o.module, block, state, given, o.writeOnly)); err != nil {
		return fail("%s", err)
	}
	return 0
}

// argValue reads a command-line value for an argument of type ty. A string
// argument takes the text as written, so version=1.10 and mode=0640 stay
// as they are, unquoting "..." if it's quoted. Anything else is read as an
// HCL literal where it is one, such as 1000, true or ["ops"].
func argValue(text string, ty cty.Type) cty.Value {
	if ty == cty.String {
		if unq, err := strconv.Unquote(text); err == nil && strings.HasPrefix(text, `"`) {
			return cty.StringVal(unq)
		}
		return cty.StringVal(text)
	}
	expr, diags := hclsyntax.ParseExpression([]byte(text), "", hcl.InitialPos)
	if !diags.HasErrors() {
		if _, isRef := expr.(*hclsyntax.ScopeTraversalExpr); !isRef {
			if v, diags := expr.Value(nil); !diags.HasErrors() && v.IsWhollyKnown() {
				return v
			}
		}
	}
	return cty.StringVal(text)
}

var notNameChar = regexp.MustCompile(`[^a-z0-9_]+`)

// stepName makes a step name from what identifies the object: etc_motd for
// path=/etc/motd, nginx for name=nginx, or the module for a hostname.
func stepName(module string, given map[string]cty.Value) string {
	for _, key := range []string{"path", "target", "name", "user", "service", "port"} {
		v, ok := given[key]
		if !ok || v.Type() != cty.String || module == "hostname" || module == "timezone" || module == "locale" {
			continue
		}
		n := strings.Trim(notNameChar.ReplaceAllString(strings.ToLower(v.AsString()), "_"), "_")
		switch {
		case n == "":
			continue
		case n[0] >= '0' && n[0] <= '9':
			return module + "_" + n
		}
		return n
	}
	return module
}

// renderStep prints the step for state, with import = true and the
// arguments as the host has them.
func renderStep(name, module string, block *configschema.Block, state cty.Value, given map[string]cty.Value, writeOnly bool) []byte {
	f := hclwrite.NewEmptyFile()
	step := f.Body().AppendNewBlock("step", []string{name}).Body()
	step.SetAttributeValue("import", cty.True)
	body := step.AppendNewBlock(module, nil).Body()

	names := make([]string, 0, len(block.Attributes))
	for n := range block.Attributes {
		names = append(names, n)
	}
	// What identifies the object first, then the rest, each alphabetically.
	sort.Slice(names, func(i, j int) bool {
		ri, rj := block.Attributes[names[i]].Required, block.Attributes[names[j]].Required
		if ri != rj {
			return ri
		}
		return names[i] < names[j]
	})
	for _, n := range names {
		attr := block.Attributes[n]
		v := state.GetAttr(n)
		if _, set := given[n]; (generateSkip[n] && !set) || (attr.Computed && !attr.Optional) || v.IsNull() || !v.IsKnown() {
			continue
		}
		if n == "content" {
			continue // below, with content_wo
		}
		body.SetAttributeValue(n, v)
	}
	if module == "file" {
		renderContent(body, state.GetAttr("content"), writeOnly)
	}
	return f.Bytes()
}

// renderContent prints a file's content: as a heredoc when it's text that
// ends in a newline, quoted when it's short text without one, and as
// content_wo with a placeholder when it's write-only, not UTF-8, or large.
func renderContent(body *hclwrite.Body, content cty.Value, writeOnly bool) {
	var why string
	switch {
	case writeOnly:
		why = "write-only: the content stayed on the host"
	case content.IsNull() || !content.IsKnown():
		return
	case !utf8.ValidString(content.AsString()):
		why = "the content isn't UTF-8 text"
	case len(content.AsString()) > maxContent:
		why = fmt.Sprintf("the content is over %d KiB", maxContent>>10)
	}
	if why != "" {
		body.AppendUnstructuredTokens(hclwrite.Tokens{
			{Type: hclsyntax.TokenComment, Bytes: []byte("# " + why + "; put it in content_wo.\n")},
		})
		body.SetAttributeValue("content_wo", cty.StringVal(contentPlaceholder))
		return
	}
	text := content.AsString()
	if !strings.HasSuffix(text, "\n") || hasLine(text, "EOT") {
		body.SetAttributeValue("content", content)
		return
	}
	// A heredoc is a template, so ${ and %{ are escaped as $${ and %%{.
	escaped := strings.NewReplacer("${", "$${", "%{", "%%{").Replace(text)
	body.SetAttributeRaw("content", hclwrite.Tokens{
		{Type: hclsyntax.TokenOHeredoc, Bytes: []byte("<<EOT\n")},
		{Type: hclsyntax.TokenStringLit, Bytes: []byte(escaped)},
		{Type: hclsyntax.TokenCHeredoc, Bytes: []byte("EOT")},
	})
}

// hasLine reports whether text has line on a line of its own, ignoring the
// whitespace around it, as HCL does when it looks for a heredoc's end.
func hasLine(text, line string) bool {
	for _, l := range strings.Split(text, "\n") {
		if strings.TrimSpace(l) == line {
			return true
		}
	}
	return false
}
