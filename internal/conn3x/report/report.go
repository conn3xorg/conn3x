// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package report builds the run report that conn3x apply -report and
// conn3x drift -report write: per host, each step and what happened to it,
// the cloud resources, any drift, and the errors as the terminal showed
// them. The format is in report.schema.json beside this file.
//
// A report holds addresses, actions, timings and errors, and never an
// attribute's value, since report files get copied to other systems.
package report

import (
	"bufio"
	"encoding/json"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/command/format"
	"github.com/opentofu/opentofu/internal/command/jsonentities"
	"github.com/opentofu/opentofu/internal/conn3x/version"
)

// FormatVersion is the report format's version. Fields are only added
// within a version.
const FormatVersion = "1"

// Report is one run.
type Report struct {
	FormatVersion string           `json:"format_version"`
	Conn3xVersion string           `json:"conn3x_version"`
	Command       string           `json:"command"`
	Started       time.Time        `json:"started"`
	Finished      time.Time        `json:"finished"`
	Success       bool             `json:"success"`
	Hosts         map[string]*Host `json:"hosts"`
	Cloud         []Resource       `json:"cloud"`
	Drift         []Drift          `json:"drift"`
	Errors        []string         `json:"errors"`
}

// Host is what happened on one host, in the order steps were planned.
type Host struct {
	Steps []Step `json:"steps"`
}

// Step is one instance of a circuit step.
type Step struct {
	Step    string   `json:"step"`
	Item    string   `json:"item,omitempty"`
	Address string   `json:"address"`
	Module  string   `json:"module"`
	Action  string   `json:"action"`
	Changed bool     `json:"changed"`
	Status  string   `json:"status"`
	Reason  string   `json:"reason,omitempty"`
	Seconds *float64 `json:"seconds,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// Resource is anything that isn't a circuit step, such as a cloud server.
type Resource struct {
	Address string   `json:"address"`
	Action  string   `json:"action"`
	Status  string   `json:"status"`
	Reason  string   `json:"reason,omitempty"`
	Seconds *float64 `json:"seconds,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// Drift is one object that changed outside Conn3x.
type Drift struct {
	Address string `json:"address"`
	Host    string `json:"host,omitempty"`
	Kind    string `json:"kind"` // "changed" or "gone"
}

// Statuses, and the reasons a step can be skipped.
const (
	StatusOK      = "ok"
	StatusFailed  = "failed"
	StatusSkipped = "skipped"

	ReasonEarlierFailed = "an earlier step failed on this host"
	ReasonRunStopped    = "the run stopped before it"
)

// New starts a report for command.
func New(command string, started time.Time) *Report {
	return &Report{
		FormatVersion: FormatVersion,
		Conn3xVersion: "v" + version.Version,
		Command:       command,
		Started:       started.UTC(),
		Hosts:         map[string]*Host{},
		Cloud:         []Resource{},
		Drift:         []Drift{},
		Errors:        []string{},
	}
}

// Where reports whether address is a circuit step and, if so, its host,
// step name ("circuit.step", after any module path) and item. A looping
// step's instance key is "host/item"; the host is taken to end at the
// first "/".
func Where(address string) (host, step, item string, ok bool) {
	mod, rest := "", address
	for strings.HasPrefix(rest, "module.") {
		i := strings.Index(rest[len("module."):], ".")
		if i < 0 {
			return "", "", "", false
		}
		// module.NAME or module.NAME["key"]
		end := len("module.") + i
		mod += rest[:end+1]
		rest = rest[end+1:]
	}
	if !strings.HasPrefix(rest, "conn3x_") {
		return "", "", "", false
	}
	dot := strings.Index(rest, ".")
	open := strings.Index(rest, `["`)
	if dot < 0 || open < dot || !strings.HasSuffix(rest, `"]`) {
		return "", "", "", false
	}
	name := rest[dot+1 : open]
	circuit, s, found := strings.Cut(name, "__")
	if !found {
		return "", "", "", false
	}
	key := rest[open+2 : len(rest)-2]
	host, item, _ = strings.Cut(key, "/")
	return host, mod + circuit + "." + s, item, true
}

// FromApply reads an apply's -json stream and fills in the steps, cloud
// resources and errors. success is whether the apply exited 0.
func (r *Report) FromApply(stream io.Reader, success bool) error {
	type entry struct {
		address, module, action string
		started, done           bool
		status, err             string
		seconds                 *float64
	}
	var order []*entry
	byAddr := map[string]*entry{}
	get := func(addr string) *entry {
		if e, ok := byAddr[addr]; ok {
			return e
		}
		e := &entry{address: addr}
		byAddr[addr] = e
		order = append(order, e)
		return e
	}

	sc := bufio.NewScanner(stream)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		var msg struct {
			Type   string `json:"type"`
			Change struct {
				Resource jsonentities.ResourceAddr `json:"resource"`
				Action   string                    `json:"action"`
			} `json:"change"`
			Hook struct {
				Resource jsonentities.ResourceAddr `json:"resource"`
				Action   string                    `json:"action"`
				Elapsed  *float64                  `json:"elapsed_seconds"`
			} `json:"hook"`
			Diagnostic *jsonentities.Diagnostic `json:"diagnostic"`
		}
		if json.Unmarshal(sc.Bytes(), &msg) != nil {
			continue
		}
		switch msg.Type {
		case "planned_change":
			if msg.Change.Action == "noop" || msg.Change.Action == "read" {
				continue
			}
			e := get(msg.Change.Resource.Addr)
			e.action, e.module = msg.Change.Action, strings.TrimPrefix(msg.Change.Resource.ResourceType, "conn3x_")
		case "apply_start":
			e := get(msg.Hook.Resource.Addr)
			e.started = true
			if e.action == "" {
				e.action = msg.Hook.Action
			}
		case "apply_complete":
			e := get(msg.Hook.Resource.Addr)
			e.started, e.done, e.status, e.seconds = true, true, StatusOK, msg.Hook.Elapsed
		case "apply_errored":
			e := get(msg.Hook.Resource.Addr)
			e.started, e.done, e.status, e.seconds = true, true, StatusFailed, msg.Hook.Elapsed
		case "diagnostic":
			d := msg.Diagnostic
			if d == nil || d.Severity != jsonentities.DiagnosticSeverityError {
				continue
			}
			// As the terminal printed it, without color.
			text := strings.TrimSpace(format.DiagnosticPlainFromJSON(d, 0))
			r.Errors = append(r.Errors, text)
			if d.Address != "" {
				if e, ok := byAddr[d.Address]; ok && e.err == "" {
					e.err = text
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}

	r.Success = success
	failedOn := map[string]bool{}
	for _, e := range order {
		if host, _, _, ok := Where(e.address); ok && e.status == StatusFailed {
			failedOn[host] = true
		}
	}
	for _, e := range order {
		status, reason := e.status, ""
		if !e.done {
			status, reason = StatusSkipped, ReasonRunStopped
		}
		host, step, item, isStep := Where(e.address)
		if status == StatusSkipped && isStep && failedOn[host] {
			reason = ReasonEarlierFailed
		}
		if !isStep {
			r.Cloud = append(r.Cloud, Resource{Address: e.address, Action: e.action, Status: status, Reason: reason, Seconds: e.seconds, Error: e.err})
			continue
		}
		h := r.Hosts[host]
		if h == nil {
			h = &Host{Steps: []Step{}}
			r.Hosts[host] = h
		}
		h.Steps = append(h.Steps, Step{
			Step: step, Item: item, Address: e.address, Module: e.module, Action: e.action,
			Changed: status == StatusOK && e.action != "noop", Status: status, Reason: reason, Seconds: e.seconds, Error: e.err,
		})
	}
	return nil
}

// AddDrift records one drifted object; a circuit step's gets its host.
func (r *Report) AddDrift(address string, gone bool) {
	kind := "changed"
	if gone {
		kind = "gone"
	}
	host, _, _, _ := Where(address)
	r.Drift = append(r.Drift, Drift{Address: address, Host: host, Kind: kind})
}

// Write finishes the report and writes it as indented JSON.
func (r *Report) Write(w io.Writer, finished time.Time) error {
	r.Finished = finished.UTC()
	sort.SliceStable(r.Drift, func(i, j int) bool { return r.Drift[i].Address < r.Drift[j].Address })
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
