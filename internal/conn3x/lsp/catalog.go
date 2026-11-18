// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package lsp

import (
	"context"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs"
	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/provider"
)

// catalog is every step module, by the name a step block uses.
type catalog map[string]*block

// block is a module, or a block nested in one.
type block struct {
	description string
	args        map[string]arg
	blocks      map[string]*block
}

type arg struct {
	typ         string
	required    bool
	description string
}

// hidden are set by the circuit or computed, so not something to write.
var hidden = map[string]bool{"id": true, "revision": true, "in_sync": true, "ssh": true, "circuit": true}

// templateDescription is the template step's, which the circuit lowers
// itself and so has no resource schema of its own.
const templateDescription = "A file rendered from a template in the circuit's directory, with templatefile syntax, and written to the host as a file step would."

// scriptArgs describe a script step's arguments, as written in a circuit.
var scriptArgs = map[string]string{
	"source":      "The program, a file in the circuit's directory, such as \"${path.module}/modules/site.py\".",
	"interpreter": "Runs the program with these first, such as [\"python3\"]. Unset runs it by its #! line.",
	"args":        "The program's arguments, an object it gets as JSON.",
	"args_wo":     "Arguments kept out of plan and state, such as a password. The program gets them in apply only.",
	"on_remove":   "\"forget\" (default) leaves the host as it is when the step is removed; \"delete\" runs the program's remove.",
}

// loadCatalog reads the modules from this binary's own provider schema, so
// what it offers always matches what conn3x validate accepts.
func loadCatalog() catalog {
	p, err := provider.New()
	if err != nil {
		return catalog{}
	}
	schemas := p.GetProviderSchema(context.Background()).ResourceTypes
	cat := catalog{}
	for name, typ := range configs.CircuitModules() {
		if s, ok := schemas[typ]; ok && s.Block != nil {
			cat[name] = fromSchema(s.Block)
		}
	}
	tmpl := &block{description: templateDescription, args: map[string]arg{}, blocks: map[string]*block{}}
	for name, required := range configs.TemplateArguments() {
		tmpl.args[name] = arg{required: required}
	}
	cat["template"] = tmpl
	// script lowers to conn3x_script, whose own attributes aren't what a
	// circuit writes.
	if sc := cat["script"]; sc != nil {
		written := &block{description: sc.description, args: map[string]arg{}, blocks: map[string]*block{}}
		for name, required := range configs.ScriptArguments() {
			written.args[name] = arg{required: required, description: scriptArgs[name]}
		}
		cat["script"] = written
	}
	return cat
}

func fromSchema(s *configschema.Block) *block {
	b := &block{description: s.Description, args: map[string]arg{}, blocks: map[string]*block{}}
	for name, a := range s.Attributes {
		if hidden[name] || (a.Computed && !a.Optional && !a.Required) {
			continue
		}
		typ := "object"
		if a.Type != cty.NilType {
			typ = a.Type.FriendlyName()
		}
		b.args[name] = arg{typ: typ, required: a.Required, description: a.Description}
	}
	for name, nb := range s.BlockTypes {
		if !hidden[name] {
			b.blocks[name] = fromSchema(&nb.Block)
		}
	}
	return b
}
