// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package configs

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/addrs"
)

// Circuits are Conn3x's playbooks. A circuit names a set of hosts and an
// ordered list of steps; each step uses one host module. Rather than adding
// a new kind of object to the graph, every step is lowered to an ordinary
// managed resource of the built-in conn3x provider:
//
//	circuit "web" { step "motd" { file { ... } } }
//
// becomes resource "conn3x_file" "web__motd", repeated with for_each over
// the circuit's hosts, with an ssh block whose host is each.value, and
// depending on the step before it. Plan, apply, state, references and drift
// detection then work exactly as they do for any other resource.

const circuitFileExt = ".circuit.hcl"

// circuitModules maps a step's module block name to its resource type.
var circuitModules = map[string]string{
	"authorized_key":   "conn3x_authorized_key",
	"known_hosts":      "conn3x_known_hosts",
	"limit":            "conn3x_limit",
	"command":          "conn3x_command",
	"cron":             "conn3x_cron",
	"timer":            "conn3x_timer",
	"sysctl":           "conn3x_sysctl",
	"hostname":         "conn3x_hostname",
	"timezone":         "conn3x_timezone",
	"locale":           "conn3x_locale",
	"firewalld":        "conn3x_firewalld",
	"ufw":              "conn3x_ufw_rule",
	"selinux_boolean":  "conn3x_selinux_boolean",
	"selinux_fcontext": "conn3x_selinux_fcontext",
	"repository":       "conn3x_repository",
	"download":         "conn3x_download",
	"archive":          "conn3x_archive",
	"git":              "conn3x_git",
	"mount":            "conn3x_mount",
	"wait_for":         "conn3x_wait_for",
	"reboot":           "conn3x_reboot",
	"directory":        "conn3x_directory",
	"link":             "conn3x_link",
	"line":             "conn3x_line",
	"block":            "conn3x_block",
	"ini":              "conn3x_ini",
	"replace":          "conn3x_replace",
	"file":             "conn3x_file",
	"package":          "conn3x_package",
	"pip":              "conn3x_pip",
	"service":          "conn3x_service",
	"user":             "conn3x_user",
	"group":            "conn3x_group",

	"eos_config":                   "conn3x_eos_config",
	"eos_hostname":                 "conn3x_eos_hostname",
	"eos_vlan":                     "conn3x_eos_vlan",
	"eos_interface":                "conn3x_eos_interface",
	"eos_user":                     "conn3x_eos_user",
	"windows_acl":                  "conn3x_windows_acl",
	"windows_ad_domain_controller": "conn3x_windows_ad_domain_controller",
	"windows_ad_forest":            "conn3x_windows_ad_forest",
	"windows_ad_group":             "conn3x_windows_ad_group",
	"windows_ad_ou":                "conn3x_windows_ad_ou",
	"windows_ad_user":              "conn3x_windows_ad_user",
	"windows_directory":            "conn3x_windows_directory",
	"windows_dns_client":           "conn3x_windows_dns_client",
	"windows_domain_membership":    "conn3x_windows_domain_membership",
	"windows_feature":              "conn3x_windows_feature",
	"windows_file":                 "conn3x_windows_file",
	"windows_group":                "conn3x_windows_group",
	"windows_iis_app_pool":         "conn3x_windows_iis_app_pool",
	"windows_iis_site":             "conn3x_windows_iis_site",
	"windows_firewall_rule":        "conn3x_windows_firewall_rule",
	"windows_package":              "conn3x_windows_package",
	"windows_powershell":           "conn3x_windows_powershell",
	"windows_reboot":               "conn3x_windows_reboot",
	"windows_update":               "conn3x_windows_update",
	"windows_registry_value":       "conn3x_windows_registry_value",
	"windows_scheduled_task":       "conn3x_windows_scheduled_task",
	"windows_service":              "conn3x_windows_service",
	"windows_user":                 "conn3x_windows_user",
	"windows_wait_for":             "conn3x_windows_wait_for",
}

// Conn3xStepModules maps each circuit step module to its resource type.
func Conn3xStepModules() map[string]string {
	out := make(map[string]string, len(circuitModules))
	for name, rt := range circuitModules {
		out[name] = rt
	}
	return out
}

// Conn3xStepResourceTypes lists the resource types circuit steps lower to.
func Conn3xStepResourceTypes() []string {
	types := make([]string, 0, len(circuitModules))
	for _, rt := range circuitModules {
		types = append(types, rt)
	}
	return types
}

var circuitSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{
		{Name: "hosts", Required: true},
		{Name: "strategy"},
	},
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "ssh"},
		{Type: "step", LabelNames: []string{"name"}},
		{Type: "handler", LabelNames: []string{"name"}},
	},
}

// circuitFileExtOf reports whether path is a circuit file.
func circuitFileExtOf(path string) string {
	if strings.HasSuffix(path, circuitFileExt) {
		return circuitFileExt
	}
	return ""
}

// decodeCircuitBlock lowers one circuit block to managed resources. seen
// tracks circuit names already declared in the same file.
func decodeCircuitBlock(block *hcl.Block, seen map[string]hcl.Range) ([]*Resource, []*Import, hcl.Diagnostics) {
	var diags hcl.Diagnostics
	name := block.Labels[0]
	if !validCircuitName(name) {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Invalid circuit name",
			Detail:   "A circuit name must be a valid identifier without a double underscore, which Conn3x uses to separate circuit and step names.",
			Subject:  &block.LabelRanges[0],
		})
		return nil, nil, diags
	}
	if prev, dup := seen[name]; dup {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Duplicate circuit",
			Detail:   fmt.Sprintf("A circuit named %q was already declared at %s. Circuit names must be unique within a module.", name, prev),
			Subject:  &block.DefRange,
		})
		return nil, nil, diags
	}
	seen[name] = block.DefRange

	content, moreDiags := block.Body.Content(circuitSchema)
	diags = append(diags, moreDiags...)
	if moreDiags.HasErrors() {
		return nil, nil, diags
	}
	hosts := content.Attributes["hosts"].Expr
	perHost, strategyDiags := circuitStrategy(content.Attributes["strategy"])
	diags = append(diags, strategyDiags...)
	if strategyDiags.HasErrors() {
		return nil, nil, diags
	}

	var sshAttrs hclsyntax.Attributes
	var sshRange hcl.Range
	switch n := len(content.Blocks.OfType("ssh")); {
	case n == 0:
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Missing ssh block",
			Detail:   "A circuit needs an ssh block that says how to log in to its hosts.",
			Subject:  &block.DefRange,
		})
		return nil, nil, diags
	case n > 1:
		second := content.Blocks.OfType("ssh")[1]
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Duplicate ssh block",
			Detail:   "A circuit has one ssh block.",
			Subject:  &second.DefRange,
		})
		return nil, nil, diags
	default:
		ssh := content.Blocks.OfType("ssh")[0]
		sshRange = ssh.DefRange
		body, ok := ssh.Body.(*hclsyntax.Body)
		if !ok {
			diags = append(diags, nativeSyntaxRequired(ssh.DefRange))
			return nil, nil, diags
		}
		if attr, ok := body.Attributes["host"]; ok {
			rng := attr.SrcRange
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Unexpected host in a circuit's ssh block",
				Detail:   "Each host's address comes from hosts, so the circuit's ssh block must not set host.",
				Subject:  &rng,
			})
			return nil, nil, diags
		}
		sshAttrs = body.Attributes
	}

	var resources []*Resource
	var imports []*Import
	steps := map[string]hcl.Range{}
	var chain []*Resource                 // the steps the next step waits for
	notifiers := map[string][]*Resource{} // handler name => steps that notify it
	notifyRefs := map[string][]hcl.Range{}
	for _, step := range content.Blocks.OfType("step") {
		stepName := step.Labels[0]
		if !validCircuitName(stepName) {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Invalid step name",
				Detail:   "A step name must be a valid identifier without a double underscore.",
				Subject:  &step.LabelRanges[0],
			})
			continue
		}
		if prev, dup := steps[stepName]; dup {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Duplicate step",
				Detail:   fmt.Sprintf("Circuit %q already has a step named %q, declared at %s.", name, stepName, prev),
				Subject:  &step.DefRange,
			})
			continue
		}
		steps[stepName] = step.DefRange

		stepHosts := hosts
		if len(chain) == 0 {
			// Checked on the first step only, so a bad host is reported once.
			stepHosts = &checkedHosts{hosts}
		}
		r, imp, stepDiags := lowerStep(name, step, stepHosts, sshAttrs, sshRange, chain, perHost)
		diags = append(diags, stepDiags...)
		if imp != nil {
			imports = append(imports, imp)
		}
		if r != nil {
			resources = append(resources, r)
			chain = chainAfter(chain, r, perHost)
			notified, notifyDiags := stepNotify(step)
			diags = append(diags, notifyDiags...)
			for _, n := range notified {
				notifiers[n.name] = append(notifiers[n.name], r)
				notifyRefs[n.name] = append(notifyRefs[n.name], n.rng)
			}
		}
	}

	diags = append(diags, warnOnConflictingEdits(content.Blocks.OfType("step"))...)

	var eosSteps []*Resource
	for _, r := range resources {
		if strings.HasPrefix(r.Type, "conn3x_eos_") {
			eosSteps = append(eosSteps, r)
		}
	}
	if len(eosSteps) > 0 {
		removals := lowerEOSRemovals(name, block, hosts, sshAttrs, sshRange)
		for _, r := range eosSteps {
			rng := block.TypeRange
			if perHost {
				rng = r.DeclRange // so Conn3xHostEdge keeps it to the step's host
			}
			r.DependsOn = append(r.DependsOn, hcl.Traversal{
				hcl.TraverseRoot{Name: removals.Type, SrcRange: rng},
				hcl.TraverseAttr{Name: removals.Name, SrcRange: rng},
			})
		}
		resources = append(resources, removals, lowerEOSCommit(name, block, hosts, sshAttrs, sshRange, eosSteps, chain, removals, perHost))
	}

	handlers := map[string]bool{}
	for _, h := range content.Blocks.OfType("handler") {
		hName := h.Labels[0]
		if !validCircuitName(hName) {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Invalid handler name",
				Detail:   "A handler name must be a valid identifier without a double underscore.",
				Subject:  &h.LabelRanges[0],
			})
			continue
		}
		if handlers[hName] {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Duplicate handler",
				Detail:   fmt.Sprintf("Circuit %q already has a handler named %q.", name, hName),
				Subject:  &h.DefRange,
			})
			continue
		}
		handlers[hName] = true
		if len(notifiers[hName]) == 0 {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagWarning,
				Summary:  "Unused handler",
				Detail:   fmt.Sprintf("No step in circuit %q notifies handler %q, so it never runs.", name, hName),
				Subject:  &h.DefRange,
			})
			continue
		}
		r, hDiags := lowerHandler(name, h, hosts, sshAttrs, sshRange, notifiers[hName], chain, perHost)
		diags = append(diags, hDiags...)
		if r != nil {
			resources = append(resources, r)
		}
	}
	for hName, ranges := range notifyRefs {
		if !handlers[hName] {
			for _, rng := range ranges {
				rng := rng
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  fmt.Sprintf("No handler %q", hName),
					Detail:   fmt.Sprintf("Circuit %q has no handler named %q.", name, hName),
					Subject:  &rng,
				})
			}
		}
	}
	return resources, imports, diags
}

func lowerStep(circuit string, step *hcl.Block, hosts hcl.Expression, sshAttrs hclsyntax.Attributes, sshRange hcl.Range, chain []*Resource, perHost bool) (*Resource, *Import, hcl.Diagnostics) {
	var diags hcl.Diagnostics
	body, ok := step.Body.(*hclsyntax.Body)
	if !ok {
		return nil, nil, append(diags, nativeSyntaxRequired(step.DefRange))
	}
	for attrName, attr := range body.Attributes {
		if attrName != "depends_on" && attrName != "notify" && attrName != "for_each" && attrName != "import" && attrName != "when" && attrName != "run_once" && attrName != "on" {
			rng := attr.SrcRange
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Unsupported argument in step",
				Detail:   fmt.Sprintf("A step takes only for_each, when, run_once, on, depends_on, notify, import, one module block and a lifecycle block, not %q.", attrName),
				Subject:  &rng,
			})
		}
	}
	var modules, lifecycles hclsyntax.Blocks
	for _, block := range body.Blocks {
		if block.Type == "lifecycle" {
			lifecycles = append(lifecycles, block)
		} else {
			modules = append(modules, block)
		}
	}
	if len(modules) > 1 {
		unsupported := false
		for _, block := range modules {
			if _, ok := circuitModules[block.Type]; ok || block.Type == "template" {
				continue
			}
			unsupported = true
			rng := block.TypeRange
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Unsupported block in step",
				Detail:   fmt.Sprintf("A step takes only for_each, when, run_once, on, depends_on, notify, import, one module block and a lifecycle block, not %q.", block.Type),
				Subject:  &rng,
			})
		}
		if unsupported {
			return nil, nil, diags
		}
	}
	if len(modules) != 1 {
		rng := step.DefRange
		return nil, nil, append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "A step needs exactly one module",
			Detail:   fmt.Sprintf("Each step contains exactly one module block, such as %s.", moduleList()),
			Subject:  &rng,
		})
	}
	module := modules[0]
	resourceType, ok := circuitModules[module.Type]
	moduleAttrs := module.Body.Attributes
	if module.Type == "template" {
		attrs, templateDiags := lowerTemplate(module)
		diags = append(diags, templateDiags...)
		if templateDiags.HasErrors() {
			return nil, nil, diags
		}
		resourceType, ok, moduleAttrs = "conn3x_file", true, attrs
	}
	if !ok {
		rng := module.TypeRange
		return nil, nil, append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("Unknown module %q", module.Type),
			Detail:   fmt.Sprintf("Supported modules are %s.", moduleList()),
			Subject:  &rng,
		})
	}
	items, looping := body.Attributes["for_each"]
	diags = append(diags, loopRefs(moduleAttrs, module.Body.Blocks, looping)...)
	if diags.HasErrors() {
		return nil, nil, diags
	}
	forEach, hostPath := hosts, []string{"value"}
	if looping {
		forEach, hostPath = &hostItemProduct{hosts: hosts, items: items.Expr}, []string{"value", "host"}
	}
	if when, ok := body.Attributes["when"]; ok {
		// each and item mean in when what they mean in the module's arguments.
		diags = append(diags, loopRefs(hclsyntax.Attributes{"when": when}, nil, looping)...)
		if diags.HasErrors() {
			return nil, nil, diags
		}
		forEach = &whenFilter{instances: forEach, cond: when.Expr}
	}
	once, onceDiags := stepRunOnce(body)
	diags = append(diags, onceDiags...)
	if onceDiags.HasErrors() {
		return nil, nil, diags
	}
	if once {
		var on hcl.Expression
		if a, ok := body.Attributes["on"]; ok {
			on = a.Expr
		}
		forEach = &onceFilter{instances: forEach, on: on, looping: looping}
	}

	ssh := sshBlockFor(sshAttrs, sshRange, hostPath)
	config := &hclsyntax.Body{
		Attributes: moduleAttrs,
		Blocks:     append(append(hclsyntax.Blocks{}, module.Body.Blocks...), ssh),
		SrcRange:   module.Body.SrcRange,
		EndRange:   module.Body.EndRange,
	}

	r := &Resource{
		Mode:      addrs.ManagedResourceMode,
		Type:      resourceType,
		Name:      circuit + "__" + step.Labels[0],
		Config:    config,
		ForEach:   forEach,
		DeclRange: step.DefRange,
		TypeRange: module.TypeRange,
		Managed:   &ManagedResource{},
	}
	if attr, ok := body.Attributes["depends_on"]; ok {
		deps, depsDiags := decodeDependsOn(attr.AsHCLAttribute())
		diags = append(diags, depsDiags...)
		r.DependsOn = append(r.DependsOn, deps...)
	}
	for _, previous := range chain {
		rng := chainRange(step, perHost)
		if stepOnce(previous.ForEach) || stepOnce(forEach) {
			// A whole-resource edge: every host waits for a run_once step,
			// and it waits for every host, as Ansible's does.
			rng = step.TypeRange
		}
		r.DependsOn = append(r.DependsOn, hcl.Traversal{
			hcl.TraverseRoot{Name: previous.Type, SrcRange: rng},
			hcl.TraverseAttr{Name: previous.Name, SrcRange: rng},
		})
	}
	if len(lifecycles) > 0 {
		diags = append(diags, stepLifecycle(r, module, lifecycles, looping)...)
	}
	var imp *Import
	if attr, ok := body.Attributes["import"]; ok {
		var importDiags hcl.Diagnostics
		imp, importDiags = stepImport(r, attr, moduleAttrs, ssh)
		diags = append(diags, importDiags...)
	}
	return r, imp, diags
}

// sshBlockFor is a step's ssh block: the circuit's settings plus this
// host's address, each.value.
// hostOverrides are the ssh settings a host object in hosts may set for
// itself, over the circuit's ssh block.
var hostOverrides = []string{"user", "port", "private_key_file", "host_key", "jump_hosts"}

// sshOnly are the ssh settings a host object can't set. Naming one in a host
// object is an error, because it would otherwise do nothing; any other field
// is the user's own data, read with each.value.
var sshOnly = []string{"host", "ssh_config_file", "known_hosts_file", "become", "become_password_file", "agent", "timeout", "confirm_after"}

// Conn3xSSHSettings lists every ssh setting circuits know about, so the
// provider can check it against its schema.
func Conn3xSSHSettings() []string {
	return append(append([]string{}, hostOverrides...), sshOnly...)
}

// sshBlockFor builds a step's ssh block. A host in hosts is either an
// address or an object with an address and any of hostOverrides:
//
//	host = try(each.value.address, each.value)
//	port = try(each.value.port, <the circuit's port, or null>)
//
// hostPath is where the host's entry sits under each: ["value"] for a plain
// step, ["value", "host"] for a looping one.
func sshBlockFor(sshAttrs hclsyntax.Attributes, sshRange hcl.Range, hostPath []string) *hclsyntax.Block {
	ssh := hclsyntax.Attributes{}
	for k, v := range sshAttrs {
		if len(hostPath) > 1 {
			// A looping step's each is the instance; the ssh block means the host.
			v = &hclsyntax.Attribute{Name: v.Name, Expr: eachMeansHost(v.Expr, v.SrcRange), SrcRange: v.SrcRange, NameRange: v.NameRange, EqualsRange: v.EqualsRange}
		}
		ssh[k] = v
	}
	attr := func(name string, expr hclsyntax.Expression) *hclsyntax.Attribute {
		return &hclsyntax.Attribute{Name: name, Expr: expr, SrcRange: sshRange, NameRange: sshRange}
	}
	try := func(args ...hclsyntax.Expression) hclsyntax.Expression {
		return &hclsyntax.FunctionCallExpr{Name: "try", Args: args, NameRange: sshRange, OpenParenRange: sshRange, CloseParenRange: sshRange}
	}
	ssh["host"] = attr("host", try(eachPath(sshRange, append(hostPath[:len(hostPath):len(hostPath)], "address")...), eachPath(sshRange, hostPath...)))
	for _, name := range hostOverrides {
		var fallback hclsyntax.Expression = &hclsyntax.LiteralValueExpr{Val: cty.NullVal(cty.DynamicPseudoType), SrcRange: sshRange}
		if a, ok := ssh[name]; ok {
			fallback = a.Expr
		}
		ssh[name] = attr(name, try(eachPath(sshRange, append(hostPath[:len(hostPath):len(hostPath)], name)...), fallback))
	}
	return &hclsyntax.Block{
		Type:            "ssh",
		Body:            &hclsyntax.Body{Attributes: ssh, SrcRange: sshRange, EndRange: sshRange},
		TypeRange:       sshRange,
		OpenBraceRange:  sshRange,
		CloseBraceRange: sshRange,
	}
}

// eachPath is each.<path...>.
func eachPath(rng hcl.Range, path ...string) *hclsyntax.ScopeTraversalExpr {
	t := hcl.Traversal{hcl.TraverseRoot{Name: "each", SrcRange: rng}}
	for _, p := range path {
		t = append(t, hcl.TraverseAttr{Name: p, SrcRange: rng})
	}
	return &hclsyntax.ScopeTraversalExpr{Traversal: t, SrcRange: rng}
}

func eachTraversal(attr string, rng hcl.Range) *hclsyntax.ScopeTraversalExpr {
	return &hclsyntax.ScopeTraversalExpr{
		Traversal: hcl.Traversal{hcl.TraverseRoot{Name: "each", SrcRange: rng}, hcl.TraverseAttr{Name: attr, SrcRange: rng}},
		SrcRange:  rng,
	}
}

type notifyRef struct {
	name string
	rng  hcl.Range
}

// stepNotify reads a step's notify = [handler.<name>, ...].
func stepNotify(step *hcl.Block) ([]notifyRef, hcl.Diagnostics) {
	body, ok := step.Body.(*hclsyntax.Body)
	if !ok {
		return nil, nil
	}
	attr, ok := body.Attributes["notify"]
	if !ok {
		return nil, nil
	}
	var diags hcl.Diagnostics
	exprs, listDiags := hcl.ExprList(attr.Expr)
	diags = append(diags, listDiags...)
	var refs []notifyRef
	for _, e := range exprs {
		tr, trDiags := hcl.AbsTraversalForExpr(e)
		if trDiags.HasErrors() || len(tr) != 2 || tr.RootName() != "handler" {
			rng := e.Range()
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Invalid notify reference",
				Detail:   "notify takes a list of handler.<name> references to handlers in the same circuit.",
				Subject:  &rng,
			})
			continue
		}
		refs = append(refs, notifyRef{name: tr[1].(hcl.TraverseAttr).Name, rng: e.Range()})
	}
	return refs, diags
}

var handlerServiceSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{{Name: "name", Required: true}, {Name: "action"}, {Name: "serial"}},
}

// lowerHandler turns a handler into a conn3x_service_action whose triggers
// are the notifying steps on the same host, so it runs only after one of
// them changed, and always after them.
func lowerHandler(circuit string, h *hcl.Block, hosts hcl.Expression, sshAttrs hclsyntax.Attributes, sshRange hcl.Range, notifiers []*Resource, chain []*Resource, perHost bool) (*Resource, hcl.Diagnostics) {
	var diags hcl.Diagnostics
	body, ok := h.Body.(*hclsyntax.Body)
	if !ok {
		return nil, append(diags, nativeSyntaxRequired(h.DefRange))
	}
	if len(body.Attributes) != 0 || len(body.Blocks) != 1 || body.Blocks[0].Type != "service" {
		rng := h.DefRange
		return nil, append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "A handler needs exactly one service block",
			Detail:   "Handlers restart or reload a service: handler \"name\" { service { name = \"nginx\" } }, with an optional action = \"reload\" and serial = true.",
			Subject:  &rng,
		})
	}
	svc := body.Blocks[0]
	if _, contentDiags := svc.Body.Content(handlerServiceSchema); contentDiags.HasErrors() {
		return nil, append(diags, contentDiags...)
	}

	rng := chainRange(h, perHost)
	triggers := hostRevisions(notifiers, rng)
	attrs := hclsyntax.Attributes{}
	for k, v := range svc.Body.Attributes {
		attrs[k] = v
	}
	attrs["triggers"] = &hclsyntax.Attribute{
		Name:      "triggers",
		Expr:      triggers,
		SrcRange:  rng,
		NameRange: rng,
	}
	r := &Resource{
		Mode:      addrs.ManagedResourceMode,
		Type:      "conn3x_service_action",
		Name:      circuit + "__" + h.Labels[0],
		Config:    &hclsyntax.Body{Attributes: attrs, Blocks: hclsyntax.Blocks{sshBlockFor(sshAttrs, sshRange, []string{"value"})}, SrcRange: svc.Body.SrcRange, EndRange: svc.Body.EndRange},
		ForEach:   hosts,
		DeclRange: h.DefRange,
		TypeRange: svc.TypeRange,
		Managed:   &ManagedResource{},
	}
	// Like Ansible, handlers run after every step in the circuit.
	for _, last := range chain {
		lrng := rng
		if stepOnce(last.ForEach) {
			lrng = h.TypeRange // every host's handler waits for the one
		}
		r.DependsOn = append(r.DependsOn, hcl.Traversal{
			hcl.TraverseRoot{Name: last.Type, SrcRange: lrng},
			hcl.TraverseAttr{Name: last.Name, SrcRange: lrng},
		})
	}
	return r, diags
}

// hostRevisions is the revisions of steps on this host, each.key: what a
// handler or an EOS commit watches, since a step's revision changes whenever
// Conn3x changes something there.
func hostRevisions(steps []*Resource, rng hcl.Range) *hclsyntax.TupleConsExpr {
	var revisions []hclsyntax.Expression
	for _, n := range steps {
		step := &hclsyntax.ScopeTraversalExpr{
			Traversal: hcl.Traversal{hcl.TraverseRoot{Name: n.Type, SrcRange: rng}, hcl.TraverseAttr{Name: n.Name, SrcRange: rng}},
			SrcRange:  rng,
		}
		// A step that loops, or has when, may have no instance on this
		// host, so it's read through a filter rather than indexed by the host.
		if stepLoops(n.ForEach) {
			revisions = append(revisions, hostInstances(step, rng))
			continue
		}
		if stepFiltered(n.ForEach) {
			revisions = append(revisions, hostInstance(step, rng))
			continue
		}
		revisions = append(revisions, &hclsyntax.RelativeTraversalExpr{
			Source: &hclsyntax.IndexExpr{
				Collection:   step,
				Key:          eachTraversal("key", rng),
				SrcRange:     rng,
				OpenRange:    rng,
				BracketRange: rng,
			},
			Traversal: hcl.Traversal{hcl.TraverseAttr{Name: "revision", SrcRange: rng}},
			SrcRange:  rng,
		})
	}
	return &hclsyntax.TupleConsExpr{Exprs: revisions, SrcRange: rng, OpenRange: rng}
}

// lowerEOSCommit adds a circuit's conn3x_eos_commit: one per switch, after
// every step on it, watching the eos steps' revisions. The eos steps only
// stage their lines in a config session; this commits that session once,
// so a switch waits confirm_after once per apply, not once per step.
//
// It also reads removals' id: a commit with one has a conn3x_eos_removals
// after it on destroy, which commits what the steps' removals staged.
func lowerEOSCommit(circuit string, block *hcl.Block, hosts hcl.Expression, sshAttrs hclsyntax.Attributes, sshRange hcl.Range, eosSteps, chain []*Resource, removals *Resource, perHost bool) *Resource {
	rng := chainRange(block, perHost)
	removalsID := &hclsyntax.RelativeTraversalExpr{
		Source: &hclsyntax.IndexExpr{
			Collection: &hclsyntax.ScopeTraversalExpr{
				Traversal: hcl.Traversal{hcl.TraverseRoot{Name: removals.Type, SrcRange: rng}, hcl.TraverseAttr{Name: removals.Name, SrcRange: rng}},
				SrcRange:  rng,
			},
			Key:          eachTraversal("key", rng),
			SrcRange:     rng,
			OpenRange:    rng,
			BracketRange: rng,
		},
		Traversal: hcl.Traversal{hcl.TraverseAttr{Name: "id", SrcRange: rng}},
		SrcRange:  rng,
	}
	r := &Resource{
		Mode: addrs.ManagedResourceMode,
		Type: "conn3x_eos_commit",
		Name: circuit + "__commit", // the type keeps it apart from a step named commit
		Config: &hclsyntax.Body{
			Attributes: hclsyntax.Attributes{
				"triggers": {Name: "triggers", Expr: hostRevisions(eosSteps, rng), SrcRange: rng, NameRange: rng},
				"removals": {Name: "removals", Expr: removalsID, SrcRange: rng, NameRange: rng},
			},
			Blocks:   hclsyntax.Blocks{sshBlockFor(sshAttrs, sshRange, []string{"value"})},
			SrcRange: block.DefRange,
			EndRange: block.DefRange,
		},
		ForEach:   hosts,
		DeclRange: block.DefRange,
		TypeRange: block.TypeRange,
		Managed:   &ManagedResource{},
	}
	for _, last := range chain {
		r.DependsOn = append(r.DependsOn, hcl.Traversal{
			hcl.TraverseRoot{Name: last.Type, SrcRange: rng},
			hcl.TraverseAttr{Name: last.Name, SrcRange: rng},
		})
	}
	return r
}

// lowerEOSRemovals adds a circuit's conn3x_eos_removals: one per switch,
// before every eos step, so that destroying the circuit removes it last.
// Destroy runs the commit first, and each step's removal after it, so the
// removals stage into one session that this commits: a switch waits
// confirm_after once, not once per removed step.
func lowerEOSRemovals(circuit string, block *hcl.Block, hosts hcl.Expression, sshAttrs hclsyntax.Attributes, sshRange hcl.Range) *Resource {
	return &Resource{
		Mode: addrs.ManagedResourceMode,
		Type: "conn3x_eos_removals",
		Name: circuit + "__removals",
		Config: &hclsyntax.Body{
			Blocks:   hclsyntax.Blocks{sshBlockFor(sshAttrs, sshRange, []string{"value"})},
			SrcRange: block.DefRange,
			EndRange: block.DefRange,
		},
		ForEach:   hosts,
		DeclRange: block.DefRange,
		TypeRange: block.TypeRange,
		Managed:   &ManagedResource{},
	}
}

var templateSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{
		{Name: "source", Required: true},
		{Name: "destination", Required: true},
		{Name: "vars"},
		{Name: "mode"},
		{Name: "owner"},
		{Name: "group"},
		{Name: "on_remove"},
		{Name: "write_only"},
		{Name: "validate"},
	},
}

// lowerTemplate turns a template module into conn3x_file arguments. The
// template renders on the controller with templatefile(), so only the
// finished bytes travel to the host:
//
//	template { source = S, destination = D, vars = V }
//	  => path = D, content = templatefile(S, V)
//
// With write_only = true the rendered file goes to content_wo instead, so it
// stays out of state.
func lowerTemplate(module *hclsyntax.Block) (hclsyntax.Attributes, hcl.Diagnostics) {
	_, diags := module.Body.Content(templateSchema)
	if diags.HasErrors() {
		return nil, diags
	}
	in := module.Body.Attributes
	out := hclsyntax.Attributes{}
	for _, name := range []string{"mode", "owner", "group", "on_remove", "validate"} {
		if a, ok := in[name]; ok {
			out[name] = a
		}
	}
	dest := in["destination"]
	out["path"] = &hclsyntax.Attribute{Name: "path", Expr: dest.Expr, SrcRange: dest.SrcRange, NameRange: dest.NameRange, EqualsRange: dest.EqualsRange}

	src := in["source"]
	var vars hclsyntax.Expression = &hclsyntax.ObjectConsExpr{SrcRange: src.SrcRange, OpenRange: src.SrcRange}
	if v, ok := in["vars"]; ok {
		vars = v.Expr
	}
	content := "content"
	if wo, ok := in["write_only"]; ok {
		v, valDiags := wo.Expr.Value(nil)
		if valDiags.HasErrors() || !v.Type().Equals(cty.Bool) || v.IsNull() {
			return nil, hcl.Diagnostics{{
				Severity: hcl.DiagError,
				Summary:  "write_only must be true or false",
				Detail:   "write_only decides how the file is stored before anything is evaluated, so it takes a literal true or false.",
				Subject:  wo.Expr.Range().Ptr(),
			}}
		}
		if v.True() {
			content = "content_wo"
		}
	}
	out[content] = &hclsyntax.Attribute{
		Name: content,
		Expr: &hclsyntax.FunctionCallExpr{
			Name:            "templatefile",
			Args:            []hclsyntax.Expression{src.Expr, vars},
			NameRange:       src.NameRange,
			OpenParenRange:  src.SrcRange,
			CloseParenRange: src.SrcRange,
		},
		SrcRange:  src.SrcRange,
		NameRange: src.NameRange,
	}
	return out, nil
}

// warnOnConflictingEdits warns when a step writes a whole file that another
// step edits in part: each apply, one undoes the other.
func warnOnConflictingEdits(steps hcl.Blocks) hcl.Diagnostics {
	var diags hcl.Diagnostics
	whole := map[string]hcl.Range{}
	parts := map[string]hcl.Range{}
	for _, step := range steps {
		body, ok := step.Body.(*hclsyntax.Body)
		if !ok {
			continue
		}
		var module *hclsyntax.Block
		for _, b := range body.Blocks {
			if b.Type != "lifecycle" {
				if module != nil {
					module = nil
					break
				}
				module = b
			}
		}
		if module == nil {
			continue
		}
		attr := module.Body.Attributes["path"]
		if module.Type == "template" {
			attr = module.Body.Attributes["destination"]
		}
		if attr == nil {
			continue
		}
		v, valDiags := attr.Expr.Value(nil)
		if valDiags.HasErrors() || !v.Type().Equals(cty.String) || v.IsNull() {
			continue // only literal paths can be compared here
		}
		switch module.Type {
		case "file", "template":
			whole[v.AsString()] = step.DefRange
		case "line", "block", "ini", "replace", "limit":
			parts[v.AsString()] = step.DefRange
		}
	}
	for path, rng := range parts {
		if wholeRange, ok := whole[path]; ok {
			rng := rng
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagWarning,
				Summary:  "File is both edited and written whole",
				Detail:   fmt.Sprintf("%s is written in full by the step at %s and edited by this step, so every apply undoes the other. Put the edit into the file's content instead.", path, wholeRange),
				Subject:  &rng,
			})
		}
	}
	return diags
}

// checkCircuitNames reports a circuit declared in more than one of a
// module's files. decodeCircuitBlock catches a repeat within one file;
// across files, the circuit headers are read again from the parsed sources,
// so a circuit with no steps still counts and the error points at the
// repeated header. The later file's resources for that circuit are dropped,
// so they aren't also reported as duplicate resources.
func checkCircuitNames(sources map[string]*hcl.File, paths []string, files []*File) hcl.Diagnostics {
	var diags hcl.Diagnostics
	declaredIn := map[string]string{}
	dropped := map[string]map[string]bool{} // filename => circuits to drop
	for _, path := range paths {
		src := sources[path]
		if src == nil {
			continue // unreadable; already reported
		}
		content, _, _ := src.Body.PartialContent(circuitHeaderSchema)
		for _, block := range content.Blocks {
			circuit := block.Labels[0]
			if !validCircuitName(circuit) {
				continue // already reported by decodeCircuitBlock
			}
			first, seen := declaredIn[circuit]
			if !seen {
				declaredIn[circuit] = path
				continue
			}
			if first == path || dropped[path][circuit] {
				continue // a repeat within one file is decodeCircuitBlock's to report
			}
			if dropped[path] == nil {
				dropped[path] = map[string]bool{}
			}
			dropped[path][circuit] = true
			rng := block.DefRange
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Duplicate circuit",
				Detail:   fmt.Sprintf("A circuit named %q was already declared in %s. Circuit names must be unique within a module.", circuit, first),
				Subject:  &rng,
			})
		}
	}
	if len(dropped) == 0 {
		return diags
	}
	for _, file := range files {
		kept := make([]*Resource, 0, len(file.ManagedResources))
		for _, r := range file.ManagedResources {
			circuit, _, lowered := strings.Cut(r.Name, "__")
			if lowered && strings.HasPrefix(r.Type, "conn3x_") && dropped[r.DeclRange.Filename][circuit] {
				continue
			}
			kept = append(kept, r)
		}
		file.ManagedResources = kept
	}
	return diags
}

// circuitHeaderSchema picks out a file's circuit blocks and nothing else.
var circuitHeaderSchema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{{Type: "circuit", LabelNames: []string{"name"}}},
}

func validCircuitName(name string) bool {
	return hclsyntax.ValidIdentifier(name) && !strings.Contains(name, "__")
}

func moduleList() string {
	names := []string{`"template"`}
	for name := range circuitModules {
		names = append(names, fmt.Sprintf("%q", name))
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func nativeSyntaxRequired(rng hcl.Range) *hcl.Diagnostic {
	return &hcl.Diagnostic{
		Severity: hcl.DiagError,
		Summary:  "Circuits need native syntax",
		Detail:   "Circuits can be written in .circuit.hcl or .tf files, but not in JSON.",
		Subject:  &rng,
	}
}

// stepRunOnce reads a step's run_once and checks on goes with it. run_once
// is written as true or false; with when it's an error for now, since it's
// unclear which should pick first.
func stepRunOnce(body *hclsyntax.Body) (bool, hcl.Diagnostics) {
	a, ok := body.Attributes["run_once"]
	on, hasOn := body.Attributes["on"]
	if !ok {
		if hasOn {
			return false, hcl.Diagnostics{{Severity: hcl.DiagError, Summary: "on without run_once",
				Detail: "on names the host a run_once step runs on; set run_once = true with it.", Subject: on.NameRange.Ptr()}}
		}
		return false, nil
	}
	v, diags := a.Expr.Value(nil)
	if diags.HasErrors() || v.Type() != cty.Bool || v.IsNull() {
		return false, hcl.Diagnostics{{Severity: hcl.DiagError, Summary: "Invalid run_once in step",
			Detail: "run_once is written as true or false.", Subject: a.Expr.Range().Ptr()}}
	}
	if v.False() {
		if hasOn {
			return false, hcl.Diagnostics{{Severity: hcl.DiagError, Summary: "on without run_once",
				Detail: "on names the host a run_once step runs on; it does nothing with run_once = false.", Subject: on.NameRange.Ptr()}}
		}
		return false, nil
	}
	if w, ok := body.Attributes["when"]; ok {
		return false, hcl.Diagnostics{{Severity: hcl.DiagError, Summary: "run_once with when",
			Detail: "A step takes run_once or when, not both, for now: it isn't settled whether when should pick the host or decide whether the one host runs it.", Subject: w.NameRange.Ptr()}}
	}
	return true, nil
}
