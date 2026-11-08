// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/configs"
	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/lint"
	"github.com/opentofu/opentofu/internal/conn3x/provider"
	"github.com/opentofu/opentofu/internal/conn3x/report"
)

// CatalogueURL is where the official circuits are listed.
var CatalogueURL = "https://conn3x.org/circuits.json"

// Tools are conn3x mcp's tools. self is the conn3x binary, which validate
// and summarise_plan run.
func Tools(self string) []Tool {
	str := func(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
	obj := func(props map[string]any, required ...string) map[string]any {
		s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
		if len(required) > 0 {
			s["required"] = required
		}
		return s
	}
	return []Tool{
		{
			Name:        "search_modules",
			Description: "Find the modules a circuit step can use, such as file, package or service, by name or by words in their description. Returns each module's name and description.",
			InputSchema: obj(map[string]any{"query": str("Words to look for, such as \"firewall\" or \"cron job\". Empty lists every module.")}),
			Run:         searchModules,
		},
		{
			Name:        "module_docs",
			Description: "One module's arguments: name, type, whether it's required, and what it does. The text is the same as the module's page on docs.conn3x.org, for this version of Conn3x.",
			InputSchema: obj(map[string]any{"module": str("The module's name, such as file or package.")}, "module"),
			Run:         moduleDocs,
		},
		{
			Name:        "search_circuits",
			Description: "Find official Conn3x circuits, ready-made configurations for things such as nginx, PostgreSQL or k3s, by name or by words in their description, category or tags. Returns each one's repository, latest version, grade and whether it passes. Reads " + CatalogueURL + ".",
			InputSchema: obj(map[string]any{"query": str("Words to look for, such as \"monitoring\" or \"postgres\". Empty lists every circuit.")}),
			Run:         searchCircuits,
		},
		{
			Name:        "validate",
			Description: "Run conn3x validate on a directory and return whether the configuration is valid, with each error and warning. Reads the files only; it doesn't connect to any host.",
			InputSchema: obj(map[string]any{"dir": str("The directory to validate. Defaults to the current one.")}),
			Run:         func(ctx context.Context, args json.RawMessage) (any, error) { return validate(ctx, self, args) },
		},
		{
			Name:        "lint",
			Description: "Run conn3x lint on a directory: the circuit grader's checks of a circuit's own code (unchecked downloads, images without a digest, listening on every address, privileged shell patterns) and command steps with no guard.",
			InputSchema: obj(map[string]any{"dir": str("The directory to lint. Defaults to the current one.")}),
			Run:         lintDir,
		},
		{
			Name:        "summarise_plan",
			Description: "Summarise a saved plan, made with conn3x plan -out=FILE: for each host, which steps it would create, change, replace or remove, and the cloud resources apart. Leaves out every attribute value. It reads the plan file; it never runs a plan, since that connects to hosts.",
			InputSchema: obj(map[string]any{
				"plan_file": str("The saved plan file."),
				"dir":       str("The configuration directory the plan was made in. Defaults to the plan file's directory."),
			}, "plan_file"),
			Run: func(ctx context.Context, args json.RawMessage) (any, error) { return summarisePlan(ctx, self, args) },
		},
	}
}

func decode(args json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(args))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("arguments: %w", err)
	}
	return nil
}

// matches reports whether every word of query is in one of texts.
func matches(query string, texts ...string) bool {
	all := strings.ToLower(strings.Join(texts, " "))
	for _, w := range strings.Fields(strings.ToLower(query)) {
		if !strings.Contains(all, w) {
			return false
		}
	}
	return true
}

func schemas() map[string]*configschema.Block {
	p, _ := provider.New()
	out := map[string]*configschema.Block{}
	for name, s := range p.GetProviderSchema(context.Background()).ResourceTypes {
		out[name] = s.Block
	}
	return out
}

const templateDescription = "A file rendered from a template in the circuit's directory, with templatefile syntax, and written to the host as a file step would."

func searchModules(_ context.Context, args json.RawMessage) (any, error) {
	var in struct {
		Query string `json:"query"`
	}
	if err := decode(args, &in); err != nil {
		return nil, err
	}
	blocks := schemas()
	var found []map[string]any
	for module, typ := range configs.CircuitModules() {
		desc := ""
		if b := blocks[typ]; b != nil {
			desc = b.Description
		}
		if matches(in.Query, module, desc) {
			found = append(found, map[string]any{"module": module, "description": desc})
		}
	}
	if matches(in.Query, "template", templateDescription) {
		found = append(found, map[string]any{"module": "template", "description": templateDescription})
	}
	sort.Slice(found, func(i, j int) bool { return found[i]["module"].(string) < found[j]["module"].(string) })
	return map[string]any{"modules": found, "count": len(found)}, nil
}

func moduleDocs(_ context.Context, args json.RawMessage) (any, error) {
	var in struct {
		Module string `json:"module"`
	}
	if err := decode(args, &in); err != nil {
		return nil, err
	}
	if in.Module == "template" {
		var argsOut []map[string]any
		for name, required := range configs.TemplateArguments() {
			argsOut = append(argsOut, map[string]any{"name": name, "required": required})
		}
		sort.Slice(argsOut, func(i, j int) bool { return argsOut[i]["name"].(string) < argsOut[j]["name"].(string) })
		return map[string]any{"module": "template", "description": templateDescription + " source is the template's path in the circuit's directory, destination the path on the host, and vars the values it reads. mode, owner, group, on_remove and validate are as for file; write_only keeps the rendered content out of state.", "arguments": argsOut}, nil
	}
	typ, ok := configs.CircuitModules()[in.Module]
	if !ok {
		return nil, fmt.Errorf("there's no module %q; search_modules lists them", in.Module)
	}
	b := schemas()[typ]
	if b == nil {
		return nil, fmt.Errorf("module %q has no schema in this build", in.Module)
	}
	var attrs []map[string]any
	for name, a := range b.Attributes {
		if name == "id" || name == "revision" {
			continue
		}
		attrs = append(attrs, map[string]any{
			"name": name, "type": a.Type.FriendlyName(), "required": a.Required,
			"optional": a.Optional, "read_only": a.Computed && !a.Optional && !a.Required,
			"description": a.Description,
		})
	}
	sort.Slice(attrs, func(i, j int) bool { return attrs[i]["name"].(string) < attrs[j]["name"].(string) })
	var blocks []map[string]any
	for name, nb := range b.BlockTypes {
		if name == "ssh" {
			continue // the circuit's ssh block fills it
		}
		blocks = append(blocks, map[string]any{"name": name, "description": nb.Block.Description})
	}
	sort.Slice(blocks, func(i, j int) bool { return blocks[i]["name"].(string) < blocks[j]["name"].(string) })
	out := map[string]any{"module": in.Module, "description": b.Description, "arguments": attrs, "page": "https://docs.conn3x.org/modules/" + in.Module}
	if len(blocks) > 0 {
		out["blocks"] = blocks
	}
	return out, nil
}

func searchCircuits(ctx context.Context, args json.RawMessage) (any, error) {
	var in struct {
		Query string `json:"query"`
	}
	if err := decode(args, &in); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, CatalogueURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("can't read the circuit catalogue at %s, which needs the network: %w", CatalogueURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the circuit catalogue at %s answered %s", CatalogueURL, resp.Status)
	}
	var cat struct {
		FormatVersion string `json:"format_version"`
		Circuits      []struct {
			Name        string   `json:"name"`
			Description string   `json:"description"`
			RepoURL     string   `json:"repo_url"`
			Version     string   `json:"version"`
			Category    string   `json:"category"`
			Tags        []string `json:"tags"`
			Grade       string   `json:"grade"`
			Passing     bool     `json:"passing"`
			Page        string   `json:"page"`
		} `json:"circuits"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cat); err != nil {
		return nil, fmt.Errorf("the circuit catalogue isn't the JSON expected: %w", err)
	}
	if cat.FormatVersion != "1" {
		return nil, fmt.Errorf("the circuit catalogue is format version %q, and this Conn3x reads version 1", cat.FormatVersion)
	}
	found := []map[string]any{}
	for _, c := range cat.Circuits {
		if !matches(in.Query, c.Name, c.Description, c.Category, strings.Join(c.Tags, " ")) {
			continue
		}
		found = append(found, map[string]any{
			"name": c.Name, "description": c.Description, "repo_url": c.RepoURL, "version": c.Version,
			"category": c.Category, "grade": c.Grade, "passing": c.Passing, "page": c.Page,
		})
	}
	return map[string]any{"circuits": found, "count": len(found)}, nil
}

func dirArg(args json.RawMessage) (string, error) {
	var in struct {
		Dir string `json:"dir"`
	}
	if err := decode(args, &in); err != nil {
		return "", err
	}
	if in.Dir == "" {
		in.Dir = "."
	}
	if st, err := os.Stat(in.Dir); err != nil || !st.IsDir() {
		return "", fmt.Errorf("%s isn't a directory", in.Dir)
	}
	return in.Dir, nil
}

// run runs conn3x with args in dir and returns its standard output.
func run(ctx context.Context, self, dir string, args ...string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, self, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TF_IN_AUTOMATION=1", "CHECKPOINT_DISABLE=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	code := 0
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		code, err = exit.ExitCode(), nil
	}
	if err != nil {
		return nil, 0, err
	}
	if code != 0 && len(bytes.TrimSpace(out)) == 0 {
		return nil, code, fmt.Errorf("conn3x %s failed: %s", args[0], strings.TrimSpace(stderr.String()))
	}
	return out, code, nil
}

func validate(ctx context.Context, self string, args json.RawMessage) (any, error) {
	dir, err := dirArg(args)
	if err != nil {
		return nil, err
	}
	out, _, err := run(ctx, self, dir, "validate", "-json", "-no-color")
	if err != nil {
		return nil, err
	}
	var res struct {
		Valid       bool `json:"valid"`
		Diagnostics []struct {
			Severity string `json:"severity"`
			Summary  string `json:"summary"`
			Detail   string `json:"detail"`
			Range    *struct {
				Filename string `json:"filename"`
				Start    struct {
					Line int `json:"line"`
				} `json:"start"`
			} `json:"range"`
		} `json:"diagnostics"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return nil, fmt.Errorf("reading conn3x validate's output: %w", err)
	}
	diags := []map[string]any{}
	for _, d := range res.Diagnostics {
		m := map[string]any{"severity": d.Severity, "summary": d.Summary}
		if d.Detail != "" {
			m["detail"] = d.Detail
		}
		if d.Range != nil {
			m["file"], m["line"] = d.Range.Filename, d.Range.Start.Line
		}
		diags = append(diags, m)
	}
	return map[string]any{"valid": res.Valid, "diagnostics": diags}, nil
}

func lintDir(_ context.Context, args json.RawMessage) (any, error) {
	dir, err := dirArg(args)
	if err != nil {
		return nil, err
	}
	found, err := lint.Dir(dir)
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for _, f := range found {
		out = append(out, map[string]any{"rule": f.Rule.ID, "name": f.Rule.Name, "severity": string(f.Rule.Severity), "file": f.File, "line": f.Line, "message": f.Message})
	}
	return map[string]any{"findings": out, "failed": lint.Failed(found)}, nil
}

func summarisePlan(ctx context.Context, self string, args json.RawMessage) (any, error) {
	var in struct {
		PlanFile string `json:"plan_file"`
		Dir      string `json:"dir"`
	}
	if err := decode(args, &in); err != nil {
		return nil, err
	}
	if in.PlanFile == "" {
		return nil, fmt.Errorf("plan_file is required")
	}
	plan, err := filepath.Abs(in.PlanFile)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(plan); err != nil {
		return nil, fmt.Errorf("can't read the plan file: %w", err)
	}
	dir := in.Dir
	if dir == "" {
		dir = filepath.Dir(plan)
	}
	out, _, err := run(ctx, self, dir, "show", "-json", plan)
	if err != nil {
		return nil, err
	}
	var p struct {
		ResourceChanges []struct {
			Address string `json:"address"`
			Change  struct {
				Actions []string `json:"actions"`
			} `json:"change"`
		} `json:"resource_changes"`
	}
	if err := json.Unmarshal(out, &p); err != nil {
		return nil, fmt.Errorf("reading the plan: %w", err)
	}
	hosts := map[string][]map[string]any{}
	cloud := []map[string]any{}
	counts := map[string]int{}
	for _, rc := range p.ResourceChanges {
		action := planAction(rc.Change.Actions)
		if action == "" {
			continue
		}
		counts[action]++
		if host, step, item, ok := report.Where(rc.Address); ok {
			s := map[string]any{"step": step, "action": action, "address": rc.Address}
			if item != "" {
				s["item"] = item
			}
			hosts[host] = append(hosts[host], s)
			continue
		}
		cloud = append(cloud, map[string]any{"address": rc.Address, "action": action})
	}
	return map[string]any{"hosts": hosts, "cloud": cloud, "counts": counts}, nil
}

// planAction names a change's actions, or "" for one that changes nothing.
func planAction(actions []string) string {
	switch strings.Join(actions, ",") {
	case "create":
		return "create"
	case "update":
		return "update"
	case "delete":
		return "remove"
	case "delete,create", "create,delete":
		return "replace"
	case "forget":
		return "forget"
	}
	return ""
}
