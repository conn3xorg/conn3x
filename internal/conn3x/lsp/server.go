// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package lsp is conn3x lsp: a Language Server Protocol server on stdio for
// circuit files, in any editor that speaks LSP. It completes step modules
// and their arguments, shows their docs on hover, and runs conn3x validate
// when a file is saved, with its errors in the file.
//
// It speaks the part of LSP that needs: Content-Length framed JSON-RPC 2.0,
// full-text document sync, completion, hover and published diagnostics.
// Like conn3x mcp, it takes no SDK for a surface this small.
package lsp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/textproto"
	"net/url"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/plugins"
)

// Server answers an editor's requests about the circuit files it has open.
type Server struct {
	Name, Version string
	// Self is the conn3x binary, which runs conn3x validate on save.
	Self string
	// AllowPlugins lets validate run in a directory with provider plugins
	// installed, which starts them. Off, such a directory isn't validated,
	// since saving a file from a repository only cloned would run what it
	// committed there.
	AllowPlugins bool

	cat  catalog
	mu   sync.Mutex
	docs map[string]string // open documents' text, by URI
	// shown are the files each directory's last validate put problems on,
	// so the next one can clear those that are fixed.
	shown map[string]map[string]bool
	// warned are the directories validate was refused in, told once.
	warned map[string]bool
	out    io.Writer
	wmu    sync.Mutex
	wg     sync.WaitGroup
}

type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// maxMessage caps one message; an open circuit file is far smaller.
const maxMessage = 32 << 20

// Serve answers messages from in on out until the editor sends exit, in
// ends, or ctx is done.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	s.cat = loadCatalog()
	s.docs = map[string]string{}
	s.shown = map[string]map[string]bool{}
	s.warned = map[string]bool{}
	s.out = out
	defer s.wg.Wait()
	r := textproto.NewReader(bufio.NewReader(in))
	for ctx.Err() == nil {
		head, err := r.ReadMIMEHeader()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading a message header: %w", err)
		}
		n, err := strconv.Atoi(head.Get("Content-Length"))
		if err != nil || n < 0 || n > maxMessage {
			return fmt.Errorf("a message has Content-Length %q", head.Get("Content-Length"))
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(r.R, body); err != nil {
			return fmt.Errorf("reading a message: %w", err)
		}
		var m message
		if err := json.Unmarshal(body, &m); err != nil {
			s.send(message{ID: json.RawMessage("null"), Error: &rpcError{-32700, "not JSON"}})
			continue
		}
		if m.Method == "exit" {
			return nil
		}
		result, rerr := s.handle(ctx, m)
		if len(m.ID) == 0 {
			continue // a notification
		}
		if rerr != nil {
			s.send(message{ID: m.ID, Error: rerr})
		} else {
			s.send(message{ID: m.ID, Result: nullable(result)})
		}
	}
	return ctx.Err()
}

// nullable keeps a nil result as JSON null, which LSP expects, rather than
// leaving result out.
func nullable(v any) any {
	if v == nil {
		return json.RawMessage("null")
	}
	return v
}

func (s *Server) send(m message) {
	m.JSONRPC = "2.0"
	b, err := json.Marshal(m)
	if err != nil {
		return
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	fmt.Fprintf(s.out, "Content-Length: %d\r\n\r\n%s", len(b), b)
}

type position struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}

type docPosition struct {
	TextDocument struct {
		URI string `json:"uri"`
	} `json:"textDocument"`
	Position position `json:"position"`
}

func (s *Server) handle(ctx context.Context, m message) (any, *rpcError) {
	switch m.Method {
	case "initialize":
		return map[string]any{
			"capabilities": map[string]any{
				"textDocumentSync":   map[string]any{"openClose": true, "change": 1, "save": map[string]any{"includeText": false}},
				"completionProvider": map[string]any{},
				"hoverProvider":      true,
			},
			"serverInfo": map[string]any{"name": s.Name, "version": s.Version},
		}, nil
	case "shutdown":
		return nil, nil
	case "textDocument/didOpen":
		var p struct {
			TextDocument struct {
				URI  string `json:"uri"`
				Text string `json:"text"`
			} `json:"textDocument"`
		}
		if json.Unmarshal(m.Params, &p) == nil {
			s.setDoc(p.TextDocument.URI, p.TextDocument.Text)
		}
	case "textDocument/didChange":
		var p struct {
			TextDocument struct {
				URI string `json:"uri"`
			} `json:"textDocument"`
			ContentChanges []struct {
				Text string `json:"text"`
			} `json:"contentChanges"`
		}
		if json.Unmarshal(m.Params, &p) == nil && len(p.ContentChanges) > 0 {
			// Full sync: the last change is the whole text.
			s.setDoc(p.TextDocument.URI, p.ContentChanges[len(p.ContentChanges)-1].Text)
		}
	case "textDocument/didClose":
		var p docPosition
		if json.Unmarshal(m.Params, &p) == nil {
			s.mu.Lock()
			delete(s.docs, p.TextDocument.URI)
			s.mu.Unlock()
		}
	case "textDocument/didSave":
		var p docPosition
		if json.Unmarshal(m.Params, &p) == nil {
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.validate(ctx, p.TextDocument.URI)
			}()
		}
	case "textDocument/completion":
		var p docPosition
		if err := json.Unmarshal(m.Params, &p); err != nil {
			return nil, &rpcError{-32602, err.Error()}
		}
		return s.complete(p), nil
	case "textDocument/hover":
		var p docPosition
		if err := json.Unmarshal(m.Params, &p); err != nil {
			return nil, &rpcError{-32602, err.Error()}
		}
		return s.hover(p), nil
	default:
		if len(m.ID) > 0 && !strings.HasPrefix(m.Method, "$/") {
			return nil, &rpcError{-32601, "conn3x lsp doesn't handle " + m.Method}
		}
	}
	return nil, nil
}

func (s *Server) setDoc(uri, text string) {
	s.mu.Lock()
	s.docs[uri] = text
	s.mu.Unlock()
}

func (s *Server) doc(uri string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.docs[uri]
}

// LSP completion item kinds.
const (
	kindModule   = 9
	kindProperty = 10
	kindStruct   = 22
)

func (s *Server) complete(p docPosition) any {
	text := s.doc(p.TextDocument.URI)
	before := text[:offset(text, p.Position.Line, p.Position.Character)]
	at, ok := where(blockPath(before), s.cat)
	items := []map[string]any{}
	if !ok {
		return items
	}
	if at.step {
		for _, name := range sortedKeys(s.cat) {
			items = append(items, map[string]any{
				"label": name, "kind": kindModule, "detail": firstSentence(s.cat[name].description),
				"documentation": docs(name, s.cat[name].description),
				"insertText":    name + " {\n  \n}", "insertTextFormat": 1,
			})
		}
		return items
	}
	set := argsSet(before)
	for _, name := range sortedKeys(at.block.args) {
		if set[name] {
			continue
		}
		a := at.block.args[name]
		detail, order := a.typ, "1"
		if a.required {
			detail, order = a.typ+", required", "0"
		}
		items = append(items, map[string]any{
			"label": name, "kind": kindProperty, "detail": strings.TrimPrefix(detail, ", "),
			"documentation": markdown(a.description), "insertText": name + " = ", "sortText": order + name,
		})
	}
	for _, name := range sortedKeys(at.block.blocks) {
		items = append(items, map[string]any{
			"label": name, "kind": kindStruct, "detail": "block",
			"documentation": markdown(at.block.blocks[name].description), "insertText": name + " {\n  \n}", "sortText": "2" + name,
		})
	}
	return items
}

func (s *Server) hover(p docPosition) any {
	text := s.doc(p.TextDocument.URI)
	i := offset(text, p.Position.Line, p.Position.Character)
	word := wordAt(text, i)
	if word == "" {
		return nil
	}
	// The block path at the start of the word's line: a module's name is
	// before its own brace.
	lineStart := strings.LastIndexByte(text[:i], '\n') + 1
	at, ok := where(blockPath(text[:lineStart]), s.cat)
	if !ok {
		return nil
	}
	if at.step {
		if b := s.cat[word]; b != nil {
			return map[string]any{"contents": docs(word, b.description)}
		}
		return nil
	}
	if a, found := at.block.args[word]; found {
		head := fmt.Sprintf("**%s** `%s`", word, a.typ)
		if a.required {
			head += ", required"
		}
		return map[string]any{"contents": markdown(head + "\n\n" + a.description + "\n\n[" + at.module + " on docs.conn3x.org](https://docs.conn3x.org/modules/" + at.module + ")")}
	}
	if b := at.block.blocks[word]; b != nil {
		return map[string]any{"contents": markdown("**" + word + "** block\n\n" + b.description)}
	}
	return nil
}

func docs(module, description string) map[string]any {
	return markdown(fmt.Sprintf("**%s**\n\n%s\n\n[On docs.conn3x.org](https://docs.conn3x.org/modules/%s)", module, description, module))
}

func markdown(v string) map[string]any { return map[string]any{"kind": "markdown", "value": v} }

func firstSentence(s string) string {
	if i := strings.Index(s, ". "); i >= 0 {
		return s[:i+1]
	}
	return s
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// validateTimeout bounds one conn3x validate run.
const validateTimeout = 60 * time.Second

// needsInit is validate stopping because conn3x init hasn't run in the
// directory yet, which isn't a problem with the file.
var needsInit = regexp.MustCompile(`(?i)not installed|conn3x init|Missing required provider|Inconsistent dependency lock file|Module not installed`)

// validate runs conn3x validate in the saved file's directory and publishes
// its errors for every file there, clearing ones that are fixed.
func (s *Server) validate(ctx context.Context, uri string) {
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "file" || s.Self == "" {
		return
	}
	dir := filepath.Dir(filepath.FromSlash(u.Path))
	if what := plugins.Installed(dir); what != "" && !s.AllowPlugins {
		s.mu.Lock()
		first := !s.warned[dir]
		s.warned[dir] = true
		s.mu.Unlock()
		if first {
			params, _ := json.Marshal(map[string]any{"type": 2, "message": fmt.Sprintf(
				"conn3x lsp didn't validate %s: it has provider plugins installed (%s), and validating would start them. Start conn3x lsp with -allow-plugins if you trust them.", dir, what)})
			s.send(message{Method: "window/showMessage", Params: params})
		}
		return
	}
	ctx, cancel := context.WithTimeout(ctx, validateTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.Self, "validate", "-json", "-no-color")
	cmd.Dir = dir
	out, _ := cmd.Output()
	var res struct {
		Diagnostics []struct {
			Severity string `json:"severity"`
			Summary  string `json:"summary"`
			Detail   string `json:"detail"`
			Range    *struct {
				Filename string `json:"filename"`
				Start    struct{ Line, Column int }
				End      struct{ Line, Column int }
			} `json:"range"`
		} `json:"diagnostics"`
	}
	if json.Unmarshal(out, &res) != nil {
		return
	}
	byFile := map[string][]map[string]any{uri: {}}
	for _, d := range res.Diagnostics {
		if needsInit.MatchString(d.Summary + " " + d.Detail) {
			return // leave what's shown; it'll be right after init
		}
		if d.Range == nil || d.Range.Filename == "" {
			continue
		}
		file := (&url.URL{Scheme: "file", Path: filepath.ToSlash(filepath.Join(dir, d.Range.Filename))}).String()
		severity := 1
		if d.Severity == "warning" {
			severity = 2
		}
		msg := d.Summary
		if d.Detail != "" {
			msg += ": " + d.Detail
		}
		byFile[file] = append(byFile[file], map[string]any{
			"range": map[string]any{
				"start": position{d.Range.Start.Line - 1, d.Range.Start.Column - 1},
				"end":   position{d.Range.End.Line - 1, d.Range.End.Column - 1},
			},
			"severity": severity, "source": "conn3x validate", "message": msg,
		})
	}
	s.mu.Lock()
	for file := range s.shown[dir] {
		if _, ok := byFile[file]; !ok {
			byFile[file] = []map[string]any{} // fixed since: clear it
		}
	}
	shown := map[string]bool{}
	for file, diags := range byFile {
		if len(diags) > 0 {
			shown[file] = true
		}
	}
	s.shown[dir] = shown
	s.mu.Unlock()
	for _, file := range sortedKeys(byFile) {
		params, _ := json.Marshal(map[string]any{"uri": file, "diagnostics": byFile[file]})
		s.send(message{Method: "textDocument/publishDiagnostics", Params: params})
	}
}
