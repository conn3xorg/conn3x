// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package jsonentities

import (
	"strings"

	"github.com/zclconf/go-cty/cty"
	ctyjson "github.com/zclconf/go-cty/cty/json"

	"github.com/opentofu/opentofu/internal/addrs"
)

type ResourceAddr struct {
	Addr            string                  `json:"addr"`
	Module          string                  `json:"module"`
	Resource        string                  `json:"resource"`
	ImpliedProvider string                  `json:"implied_provider"`
	ResourceType    string                  `json:"resource_type"`
	ResourceName    string                  `json:"resource_name"`
	ResourceKey     ctyjson.SimpleJSONValue `json:"resource_key"`
	Conn3x          *Conn3xStep             `json:"conn3x,omitempty"`
}

// Conn3xStep names the circuit step or handler a resource instance runs and
// the host it runs on, so a reader needn't parse the generated address.
type Conn3xStep struct {
	Circuit string `json:"circuit"`
	Step    string `json:"step"`
	Host    string `json:"host"`
	Item    string `json:"item,omitempty"`
}

// conn3xStep reads a circuit's generated name, CIRCUIT__STEP keyed by HOST
// or HOST/ITEM. Neither name may hold "__", and no host "/", so it's exact.
func conn3xStep(r addrs.ResourceInstance) *Conn3xStep {
	if r.Resource.Mode != addrs.ManagedResourceMode || !strings.HasPrefix(r.Resource.Type, "conn3x_") {
		return nil
	}
	circuit, step, ok := strings.Cut(r.Resource.Name, "__")
	key, isString := r.Key.(addrs.StringKey)
	if !ok || !isString {
		return nil
	}
	host, item, _ := strings.Cut(string(key), "/")
	return &Conn3xStep{Circuit: circuit, Step: step, Host: host, Item: item}
}

func NewResourceAddr(addr addrs.AbsResourceInstance) ResourceAddr {
	resourceKey := ctyjson.SimpleJSONValue{Value: cty.NilVal}
	if addr.Resource.Key != nil {
		resourceKey.Value = addr.Resource.Key.Value()
	}
	return ResourceAddr{
		Addr:            addr.String(),
		Module:          addr.Module.String(),
		Resource:        addr.Resource.String(),
		ImpliedProvider: addr.Resource.Resource.ImpliedProvider(),
		ResourceType:    addr.Resource.Resource.Type,
		ResourceName:    addr.Resource.Resource.Name,
		ResourceKey:     resourceKey,
		Conn3x:          conn3xStep(addr.Resource),
	}
}
