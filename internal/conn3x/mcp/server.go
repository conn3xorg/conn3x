// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package mcp is conn3x mcp: a Model Context Protocol server on stdio that
// lets an assistant look up Conn3x's modules and circuits, validate and
// lint a circuit, and summarise a saved plan. Nothing in it applies or
// writes state.
//
// It speaks the part of MCP a tools-only server needs, JSON-RPC 2.0 lines
// on stdio: initialize, ping, tools/list and tools/call. The official Go
// SDK was weighed for this and left out: it added 1.5 MB to the binary,
// two thirds of what's left under the size check against tofu, and four
// modules, for a surface this small.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// protocolVersions are the MCP revisions this server speaks, newest first.
var protocolVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

// Tool is one tool: its description and input schema for tools/list, and
// what it does.
type Tool struct {
	Name        string
	Description string
	InputSchema map[string]any
	Run         func(ctx context.Context, args json.RawMessage) (any, error)
}

// Server answers MCP requests with its tools.
type Server struct {
	Name, Version string
	Tools         []Tool
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// JSON-RPC error codes.
const (
	parseError     = -32700
	invalidRequest = -32600
	methodNotFound = -32601
	invalidParams  = -32602
)

// Serve reads requests from in, one JSON object per line, and writes the
// responses to out until in ends or ctx is done. Notifications, which have
// no id, get no response.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	var mu sync.Mutex
	enc := json.NewEncoder(out)
	send := func(r response) {
		mu.Lock()
		defer mu.Unlock()
		_ = enc.Encode(r)
	}
	for sc.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			send(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{parseError, "not JSON: " + err.Error()}})
			continue
		}
		if req.JSONRPC != "2.0" || req.Method == "" {
			if len(req.ID) > 0 {
				send(response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{invalidRequest, "not a JSON-RPC 2.0 request"}})
			}
			continue
		}
		if len(req.ID) == 0 {
			continue // a notification, such as notifications/initialized
		}
		result, rerr := s.handle(ctx, req)
		send(response{JSONRPC: "2.0", ID: req.ID, Result: result, Error: rerr})
	}
	return sc.Err()
}

func (s *Server) handle(ctx context.Context, req request) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		version := protocolVersions[0]
		for _, v := range protocolVersions {
			if v == p.ProtocolVersion {
				version = v
			}
		}
		return map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": s.Name, "version": s.Version},
			"instructions":    "Conn3x configures servers from circuits. These tools look up modules and official circuits, validate and lint a circuit directory, and summarise a saved plan. None of them applies anything.",
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		tools := make([]map[string]any, 0, len(s.Tools))
		for _, t := range s.Tools {
			tools = append(tools, map[string]any{"name": t.Name, "description": t.Description, "inputSchema": t.InputSchema})
		}
		return map[string]any{"tools": tools}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
			return nil, &rpcError{invalidParams, "tools/call needs a tool name"}
		}
		for _, t := range s.Tools {
			if t.Name != p.Name {
				continue
			}
			args := p.Arguments
			if len(args) == 0 {
				args = json.RawMessage("{}")
			}
			out, err := t.Run(ctx, args)
			if err != nil {
				// A tool's failure is a result the assistant reads, not a
				// protocol error.
				return toolResult(map[string]any{"error": err.Error()}, true), nil
			}
			return toolResult(out, false), nil
		}
		return nil, &rpcError{invalidParams, fmt.Sprintf("there's no tool %q", p.Name)}
	}
	return nil, &rpcError{methodNotFound, fmt.Sprintf("conn3x mcp doesn't handle %q", req.Method)}
}

// toolResult wraps a tool's output as MCP content: the JSON as text, which
// every client reads, and as structuredContent.
func toolResult(out any, isError bool) map[string]any {
	text, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		text, isError = []byte(err.Error()), true
	}
	res := map[string]any{
		"content": []map[string]any{{"type": "text", "text": string(text)}},
		"isError": isError,
	}
	if m, ok := out.(map[string]any); ok {
		res["structuredContent"] = m
	}
	return res
}
