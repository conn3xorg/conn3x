// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package lint checks a circuit's files for what the circuit grader marks
// down in a circuit's own code, plus a few things only a reader of the
// steps can see. The grader's checks are line-based, and so are these, with
// the same patterns, so a circuit that lints clean passes those checks. The
// cases in testdata/grader-cases.json are checked here and by the grader's
// tests in conn3xorg/web, which keeps the two the same.
package lint

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// Severity is how a finding counts: an error fails the run, a warning
// doesn't.
type Severity string

const (
	Error   Severity = "error"
	Warning Severity = "warning"
)

// Rule is one check.
type Rule struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Severity Severity `json:"severity"`
}

var (
	DownloadChecksum = Rule{"C3X001", "download-checksum", Error}
	ImageDigest      = Rule{"C3X002", "image-digest", Error}
	ListenAll        = Rule{"C3X003", "listen-all", Error}
	PrivilegedShell  = Rule{"C3X004", "privileged-shell", Error}
	CommandGuard     = Rule{"C3X101", "command-guard", Warning}
	BadIgnore        = Rule{"C3X900", "ignore", Error}
)

// Rules are every rule, by ID.
var Rules = map[string]Rule{}

func init() {
	for _, r := range []Rule{DownloadChecksum, ImageDigest, ListenAll, PrivilegedShell, CommandGuard, BadIgnore} {
		Rules[r.ID] = r
	}
}

// Finding is one problem at one place.
type Finding struct {
	Rule    Rule   `json:"rule"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Message string `json:"message"`
}

func (f Finding) String() string {
	return fmt.Sprintf("%s:%d:%d: %s %s: %s", f.File, f.Line, f.Column, f.Rule.ID, f.Rule.Name, f.Message)
}

// The grader's patterns, from apps/site/src/lib/grades.js in conn3xorg/web.
// RE2 has no lookaround, so the few that use it are checked in code below,
// to the same effect.
var (
	commentLine = regexp.MustCompile(`^\s*(#|//)`)
	proseLine   = regexp.MustCompile(`^\s*(description|error_message)\s*=`)
	valueLine   = regexp.MustCompile(`^\s*value\s*=`)

	image = regexp.MustCompile(`"(?:docker\.io|ghcr\.io|quay\.io|registry\.[\w.-]+|mcr\.microsoft\.com)/[^"\s]+"`)
	tag   = regexp.MustCompile(`:[^/]+"$`)

	handled   = regexp.MustCompile(`\b(lookup|contains|setintersection|replace|coalesce)\(|[!=]=\s*"`)
	listenAll = regexp.MustCompile(`\bdefault\s*=\s*\[?\s*"(::|\[::\]|\*)(:\d+)?"|0\.0\.0\.0([^/\d]|$)|--[\w.-]*(listen|bind|addr)[\w-]*=:`)

	privileged = []struct {
		re   *regexp.Regexp
		what string
	}{
		{regexp.MustCompile(`\b(?:curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:ba|da|z)?sh\b`), "pipes a download into a shell"},
		{regexp.MustCompile(`--(?:password|passwd|pass|token|secret|api-key)[ =]\\?"?\$`), "puts a secret on a command line, where ps can read it"},
		{regexp.MustCompile(`\bchmod\s+(?:-R\s+)?(?:0?777|0?666|a\+w|o\+w)(\s|$)`), "makes a path writable by everyone"},
		{regexp.MustCompile(`(?:>|\btee\s+)\s*/tmp/[\w.$]`), "writes to a predictable name in /tmp"}, // not on an Exec= line, below
		{regexp.MustCompile(`--allow-root\b`), "tells a tool that refuses root to run as root anyway"},
		{regexp.MustCompile(`--no-check-certificate|--allow-unauthenticated|\[trusted=yes\]`), "installs or downloads without checking the source"},
	}
	commandSep = regexp.MustCompile(`[|;&]`)
	curl       = regexp.MustCompile(`\bcurl\b`)
	insecure   = regexp.MustCompile(`\s(?:-[a-zA-Z]*k[a-zA-Z]*|--insecure)(\s|$)`)
	credential = regexp.MustCompile(`\s(?:-[a-zA-Z]*K|--config\b|-u\s|--user\b|-H\s*["']?(?:Authorization|X-[A-Za-z-]*(?:Token|Key))|--cert\b|--cookie\b|--oauth2-bearer\b)`)

	downloadStart = regexp.MustCompile(`\b(?:download|windows_package)\s*\{`)
	urlAttr       = regexp.MustCompile(`\burl\s*=`)
	shaAttr       = regexp.MustCompile(`\bsha256\s*=`)

	ignoreRe = regexp.MustCompile(`(?:#|//)\s*conn3x-lint:ignore\s+(C3X\d{3})\s*(.*)$`)
)

// insecureCredential is the grader's INSECURE_CREDENTIAL: on one command,
// curl, an insecure flag and a credential.
func insecureCredential(line string) bool {
	for _, cmd := range commandSep.Split(line, -1) {
		if curl.MatchString(cmd) && insecure.MatchString(cmd) && credential.MatchString(cmd) {
			return true
		}
	}
	return false
}

// Dir lints every .hcl, .tf and .sh file under dir, leaving out examples/
// and test/ as the grader does.
func Dir(dir string) ([]Finding, error) {
	var findings []Finding
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".terraform", "node_modules":
				return filepath.SkipDir
			}
			if rel == "examples" || rel == "test" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".hcl" && ext != ".tf" && ext != ".sh" {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		findings = append(findings, File(path, src)...)
		return nil
	})
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	return findings, err
}

// File lints one file's source. Its extension decides which rules apply.
func File(path string, src []byte) []Finding {
	ext := filepath.Ext(path)
	lines := strings.Split(string(src), "\n")
	var found []Finding
	add := func(r Rule, line, col int, msg string) {
		found = append(found, Finding{Rule: r, File: path, Line: line, Column: col, Message: msg})
	}

	for i, l := range lines {
		n := i + 1
		if commentLine.MatchString(l) {
			continue
		}
		prose := proseLine.MatchString(l)
		if (ext == ".hcl" || ext == ".tf") && !prose {
			if !valueLine.MatchString(l) {
				for _, loc := range image.FindAllStringIndex(l, -1) {
					ref := l[loc[0]:loc[1]]
					if !strings.Contains(ref, "@") && tag.MatchString(ref) {
						add(ImageDigest, n, loc[0]+1, fmt.Sprintf("image %s has a tag and no digest; pin it as name:tag@sha256:...", ref))
					}
				}
			}
			if !handled.MatchString(l) {
				if loc := listenAll.FindStringIndex(l); loc != nil {
					add(ListenAll, n, loc[0]+1, "listens on every address by default; make the caller choose the address, or default to 127.0.0.1")
				}
			}
		}
		if (ext == ".hcl" || ext == ".tf" || ext == ".sh") && !prose {
			for _, p := range privileged {
				if loc := p.re.FindStringIndex(l); loc != nil {
					if p.what == "writes to a predictable name in /tmp" && strings.Contains(l, "Exec=") {
						continue
					}
					add(PrivilegedShell, n, loc[0]+1, "shell here "+p.what)
				}
			}
			if insecureCredential(l) {
				add(PrivilegedShell, n, curl.FindStringIndex(l)[0]+1, "shell here sends a credential with the certificate check off")
			}
		}
	}

	if ext == ".hcl" {
		// The grader reads downloads with comment lines taken out.
		code := make([]string, len(lines))
		for i, l := range lines {
			if !commentLine.MatchString(l) {
				code[i] = l
			}
		}
		found = append(found, downloads(path, strings.Join(code, "\n"))...)
		found = append(found, commandGuards(path, src)...)
	}
	return applyIgnores(path, lines, found)
}

// downloads is the grader's download check, per block: a download step, or
// a windows_package with a url, needs a sha256.
func downloads(path, src string) []Finding {
	var out []Finding
	for _, m := range downloadStart.FindAllStringIndex(src, -1) {
		depth, i := 0, m[1]-1
		for {
			switch src[i] {
			case '{':
				depth++
			case '}':
				depth--
			}
			i++
			if depth == 0 || i >= len(src) {
				break
			}
		}
		block := src[m[0]:i]
		if strings.HasPrefix(block, "windows_package") && !urlAttr.MatchString(block) {
			continue
		}
		if shaAttr.MatchString(block) {
			continue
		}
		line := strings.Count(src[:m[0]], "\n") + 1
		col := m[0] - strings.LastIndex(src[:m[0]], "\n")
		what := "download step"
		if strings.HasPrefix(block, "windows_package") {
			what = "windows_package step with a url"
		}
		out = append(out, Finding{Rule: DownloadChecksum, File: path, Line: line, Column: col, Message: what + " has no sha256, so a changed or tampered file installs anyway"})
	}
	return out
}

// commandGuards finds command steps with nothing for Conn3x to read back:
// no creates, removes or unless, and no triggers. Such a command runs when
// the step is created and again only when command changes, so if its work
// is undone on the host, no plan notices. A command with triggers means to
// run again when something changes, like a reload, and is left alone.
func commandGuards(path string, src []byte) []Finding {
	f, diags := hclsyntax.ParseConfig(src, path, hcl.InitialPos)
	if diags.HasErrors() {
		return nil // the loader reports syntax errors
	}
	var out []Finding
	var walk func(b *hclsyntax.Body, inStep string)
	walk = func(b *hclsyntax.Body, inStep string) {
		for _, blk := range b.Blocks {
			step := inStep
			if blk.Type == "step" && len(blk.Labels) == 1 {
				step = blk.Labels[0]
			}
			if blk.Type == "command" && inStep != "" {
				a := blk.Body.Attributes
				if a["creates"] == nil && a["removes"] == nil && a["unless"] == nil && a["triggers"] == nil {
					r := blk.TypeRange
					out = append(out, Finding{Rule: CommandGuard, File: path, Line: r.Start.Line, Column: r.Start.Column,
						Message: fmt.Sprintf("command in step %q has no creates, removes, unless or triggers, so it ran once and no plan can tell if its work is undone; add a guard that checks it", inStep)})
				}
			}
			walk(blk.Body, step)
		}
	}
	walk(f.Body.(*hclsyntax.Body), "")
	return out
}

// applyIgnores drops findings an ignore comment covers, on their line or the
// line above, and reports ignores with no reason or nothing to ignore.
func applyIgnores(path string, lines []string, found []Finding) []Finding {
	type ignore struct {
		id, reason string
		line       int
		used       bool
	}
	var ignores []*ignore
	for i, l := range lines {
		if m := ignoreRe.FindStringSubmatch(l); m != nil {
			ignores = append(ignores, &ignore{id: m[1], reason: strings.TrimSpace(m[2]), line: i + 1})
		}
	}
	var out []Finding
	for _, f := range found {
		covered := false
		for _, ig := range ignores {
			if ig.id == f.Rule.ID && (ig.line == f.Line || ig.line == f.Line-1) {
				ig.used, covered = true, true
			}
		}
		if !covered {
			out = append(out, f)
		}
	}
	for _, ig := range ignores {
		switch {
		case Rules[ig.id].ID == "":
			out = append(out, Finding{Rule: BadIgnore, File: path, Line: ig.line, Column: 1, Message: fmt.Sprintf("ignore names %s, which isn't a rule", ig.id)})
		case ig.reason == "":
			out = append(out, Finding{Rule: BadIgnore, File: path, Line: ig.line, Column: 1, Message: fmt.Sprintf("ignore of %s gives no reason; say why after the rule ID", ig.id)})
		case !ig.used:
			out = append(out, Finding{Rule: BadIgnore, File: path, Line: ig.line, Column: 1, Message: fmt.Sprintf("ignore of %s matches nothing on this line or the next; remove it", ig.id)})
		}
	}
	return out
}

// Failed reports whether any finding is an error.
func Failed(findings []Finding) bool {
	for _, f := range findings {
		if f.Rule.Severity == Error {
			return true
		}
	}
	return false
}
