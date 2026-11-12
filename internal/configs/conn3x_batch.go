// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package configs

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// Conn3xBatch is how a circuit rolls out: batch by batch, as with Ansible's
// serial, stopping once more than MaxFailures hosts have failed.
type Conn3xBatch struct {
	Circuit       string
	Size          int // hosts per batch, when Percent is 0
	Percent       int // hosts per batch as a percentage of the hosts that change
	MaxFailures   int // when FailedPercent is 0
	FailedPercent int // MaxFailures as a percentage of the hosts that change
}

// FailuresOf is how many of n hosts that change may fail: FailedPercent
// of them, rounded down, as Ansible's max_fail_percentage does.
func (b Conn3xBatch) FailuresOf(n int) int {
	if b.FailedPercent > 0 {
		return n * b.FailedPercent / 100
	}
	return b.MaxFailures
}

// ParseConn3xMaxFailures reads max_failures: a whole number of hosts, 0 or
// more, or a percentage such as "20%". "0%" is 0 hosts.
func ParseConn3xMaxFailures(s string) (n, percent int, err error) {
	if p, ok := strings.CutSuffix(s, "%"); ok {
		percent, err = strconv.Atoi(p)
		if err != nil || percent < 0 || percent > 100 {
			return 0, 0, fmt.Errorf("%q isn't a percentage from 0%% to 100%%", s)
		}
		return 0, percent, nil
	}
	n, err = strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, 0, fmt.Errorf("%q isn't a number of hosts, 0 or more, or a percentage such as \"20%%\"", s)
	}
	return n, 0, nil
}

// Of is the batch size for n hosts that change: at least one.
func (b Conn3xBatch) Of(n int) int {
	size := b.Size
	if b.Percent > 0 {
		size = int(math.Ceil(float64(n) * float64(b.Percent) / 100))
	}
	return max(size, 1)
}

// ParseConn3xBatchSize reads a batch size: a whole number of hosts, or a
// percentage such as "20%".
func ParseConn3xBatchSize(s string) (size, percent int, err error) {
	if p, ok := strings.CutSuffix(s, "%"); ok {
		percent, err = strconv.Atoi(p)
		if err != nil || percent < 1 || percent > 100 {
			return 0, 0, fmt.Errorf("%q isn't a percentage from 1%% to 100%%", s)
		}
		return 0, percent, nil
	}
	size, err = strconv.Atoi(s)
	if err != nil || size < 1 {
		return 0, 0, fmt.Errorf("%q isn't a number of hosts or a percentage such as \"20%%\"", s)
	}
	return size, 0, nil
}

// circuitBatch reads a circuit's batch_size and max_failures. They're
// constants, since apply reads them before anything is evaluated.
func circuitBatch(name string, content *hcl.BodyContent, perHost bool) (*Conn3xBatch, hcl.Diagnostics) {
	sizeAttr, failAttr := content.Attributes["batch_size"], content.Attributes["max_failures"]
	if sizeAttr == nil {
		if failAttr != nil {
			return nil, hcl.Diagnostics{{
				Severity: hcl.DiagError,
				Summary:  "max_failures without batch_size",
				Detail:   "max_failures is how many hosts may fail before no more batches start, so it needs batch_size.",
				Subject:  failAttr.Range.Ptr(),
			}}
		}
		return nil, nil
	}
	b := &Conn3xBatch{Circuit: name}
	bad := func(attr *hcl.Attribute, detail string) (*Conn3xBatch, hcl.Diagnostics) {
		return nil, hcl.Diagnostics{{Severity: hcl.DiagError, Summary: "Invalid " + attr.Name, Detail: detail, Subject: attr.Expr.Range().Ptr()}}
	}
	if !perHost {
		return bad(sizeAttr, `A circuit runs in batches only with strategy = "per_host", where each host's steps run on their own.`)
	}
	raw, ok := constantText(sizeAttr)
	if !ok {
		return bad(sizeAttr, `batch_size must be a constant: a number of hosts, or a percentage such as "20%".`)
	}
	var err error
	if b.Size, b.Percent, err = ParseConn3xBatchSize(raw); err != nil {
		return bad(sizeAttr, "batch_size: "+err.Error()+".")
	}
	if failAttr != nil {
		raw, ok := constantText(failAttr)
		if !ok {
			return bad(failAttr, `max_failures must be a constant: a number of hosts, 0 or more, or a percentage such as "20%".`)
		}
		if b.MaxFailures, b.FailedPercent, err = ParseConn3xMaxFailures(raw); err != nil {
			return bad(failAttr, "max_failures: "+err.Error()+".")
		}
	}
	return b, nil
}

// constantText is a constant number or string attribute as text.
func constantText(attr *hcl.Attribute) (string, bool) {
	v, diags := attr.Expr.Value(nil)
	if diags.HasErrors() || !v.IsKnown() || v.IsNull() {
		return "", false
	}
	switch v.Type() {
	case cty.Number:
		return v.AsBigFloat().Text('f', -1), true
	case cty.String:
		return v.AsString(), true
	}
	return "", false
}

// batchRefusesRunOnce refuses a run_once step in a batched circuit: it runs
// on one host of the whole circuit, which no single batch holds.
func batchRefusesRunOnce(steps hcl.Blocks) hcl.Diagnostics {
	var diags hcl.Diagnostics
	for _, step := range steps {
		body, ok := step.Body.(*hclsyntax.Body)
		if !ok {
			continue
		}
		if a, ok := body.Attributes["run_once"]; ok {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "run_once in a batched circuit",
				Detail:   "A run_once step runs on one host of the whole circuit, and a batch holds only some of them. Move it to a circuit without batch_size.",
				Subject:  a.SrcRange.Ptr(),
			})
		}
	}
	return diags
}

// Conn3xBatches reads the batched circuits in the root module in dir. It
// reads only what batching needs; the full checks run when the
// configuration loads.
func Conn3xBatches(dir string) ([]Conn3xBatch, hcl.Diagnostics) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, hcl.Diagnostics{{Severity: hcl.DiagError, Summary: "Can't read the configuration directory", Detail: err.Error()}}
	}
	var out []Conn3xBatch
	var diags hcl.Diagnostics
	p := hclparse.NewParser()
	for _, e := range entries {
		if e.IsDir() || circuitFileExtOf(e.Name()) == "" {
			continue
		}
		f, fDiags := p.ParseHCLFile(filepath.Join(dir, e.Name()))
		diags = append(diags, fDiags...)
		if f == nil {
			continue
		}
		top, _, _ := f.Body.PartialContent(&hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "circuit", LabelNames: []string{"name"}}}})
		for _, block := range top.Blocks {
			content, _, _ := block.Body.PartialContent(circuitSchema)
			perHost, _ := circuitStrategy(content.Attributes["strategy"])
			b, bDiags := circuitBatch(block.Labels[0], content, perHost)
			diags = append(diags, bDiags...)
			if b != nil {
				out = append(out, *b)
			}
		}
	}
	return out, diags
}
