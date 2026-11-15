// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package jsonstep names the circuit step and host a resource instance is,
// for the conn3x object on each resource in the -json stream. The brand
// patch adds it to upstream's jsonentities.ResourceAddr.
package jsonstep

import (
	"strings"

	"github.com/opentofu/opentofu/internal/addrs"
)

// Step is the circuit step or handler a resource instance runs and the
// host it runs on, so a reader needn't parse the generated address.
type Step struct {
	Circuit string `json:"circuit"`
	Step    string `json:"step"`
	Host    string `json:"host"`
	Item    string `json:"item,omitempty"`
}

// Of reads a circuit's generated name, CIRCUIT__STEP keyed by HOST or
// HOST/ITEM, or returns nil for any other resource. Neither name may hold
// "__", and no host "/", so it's exact.
func Of(addr addrs.AbsResourceInstance) *Step {
	r := addr.Resource
	if r.Resource.Mode != addrs.ManagedResourceMode || !strings.HasPrefix(r.Resource.Type, "conn3x_") {
		return nil
	}
	circuit, step, ok := strings.Cut(r.Resource.Name, "__")
	key, isString := r.Key.(addrs.StringKey)
	if !ok || !isString {
		return nil
	}
	host, item, _ := strings.Cut(string(key), "/")
	return &Step{Circuit: circuit, Step: step, Host: host, Item: item}
}
