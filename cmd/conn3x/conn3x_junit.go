// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bufio"
	"cmp"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/command"
)

const junitFlagHelp = "Write the results as JUnit XML to this file, for CI dashboards: a test suite per test file, a test case per run block, and each failure's errors."

// withJUnit gives test a -junit-xml flag. The test runs as before, with its
// -json stream also sent to a temporary file through -json-into (or to the
// caller's own -json-into file), and the XML is built from that stream.
func withJUnit(cmd *command.Command) {
	var path string
	cmd.CommandLine.StringVar(&path, "junit-xml", "", junitFlagHelp).SetDisplay("=results.xml")
	view := cmd.CommandLine.View
	run := cmd.Run
	cmd.Run = func(m command.Meta) int {
		if path == "" {
			return run(m)
		}
		var stream string
		if view.JSONInto != nil {
			stream = view.JSONInto.Name()
		} else {
			tmp, err := os.CreateTemp("", "conn3x-junit-*.json")
			if err != nil {
				fmt.Fprintf(stderr, "Error: making a file for the test's stream: %s\n", err)
				return 1
			}
			defer os.Remove(tmp.Name())
			defer tmp.Close()
			view.JSONInto, stream = tmp, tmp.Name()
		}
		code := run(m)
		if err := writeJUnit(path, stream); err != nil {
			fmt.Fprintf(stderr, "Error: writing %s: %s\n", path, err)
			if code == 0 {
				code = 1
			}
		}
		return code
	}
}

type junitSuites struct {
	XMLName  xml.Name     `xml:"testsuites"`
	Tests    int          `xml:"tests,attr"`
	Failures int          `xml:"failures,attr"`
	Errors   int          `xml:"errors,attr"`
	Skipped  int          `xml:"skipped,attr"`
	Suites   []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Errors   int         `xml:"errors,attr"`
	Skipped  int         `xml:"skipped,attr"`
	Time     string      `xml:"time,attr"`
	Cases    []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *junitProblem `xml:"failure,omitempty"`
	Error     *junitProblem `xml:"error,omitempty"`
	Skipped   *struct{}     `xml:"skipped,omitempty"`
}

type junitProblem struct {
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

// junitLine is what the XML needs from one line of the test's JSON stream.
type junitLine struct {
	Level     string    `json:"@level"`
	Timestamp time.Time `json:"@timestamp"`
	Type      string    `json:"type"`
	File      string    `json:"@testfile"`
	Run       string    `json:"@testrun"`
	TestRun   *struct {
		Path, Run, Status string
	} `json:"test_run"`
	Diagnostic *struct {
		Severity, Summary, Detail string
	} `json:"diagnostic"`
}

// junitFrom builds the XML from a test's JSON stream. A run's time is from
// the line before it in the same file to its own result, since the stream
// doesn't say when a run starts.
func junitFrom(r io.Reader) (junitSuites, error) {
	var out junitSuites
	suites := map[string]*junitSuite{}
	var order []string
	last := map[string]time.Time{}
	errs := map[[2]string][]string{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		var l junitLine
		if json.Unmarshal(sc.Bytes(), &l) != nil {
			continue
		}
		if l.File != "" {
			if _, ok := suites[l.File]; !ok {
				suites[l.File] = &junitSuite{Name: l.File}
				order = append(order, l.File)
				last[l.File] = l.Timestamp
			}
		}
		if d := l.Diagnostic; d != nil && d.Severity == "error" && l.File != "" {
			msg := d.Summary
			if d.Detail != "" {
				msg += ": " + d.Detail
			}
			errs[[2]string{l.File, l.Run}] = append(errs[[2]string{l.File, l.Run}], msg)
		}
		tr := l.TestRun
		if l.Type != "test_run" || tr == nil {
			continue
		}
		s := suites[tr.Path]
		if s == nil {
			s = &junitSuite{Name: tr.Path}
			suites[tr.Path], last[tr.Path] = s, l.Timestamp
			order = append(order, tr.Path)
		}
		c := junitCase{Name: tr.Run, Classname: tr.Path, Time: seconds(l.Timestamp.Sub(last[tr.Path]))}
		last[tr.Path] = l.Timestamp
		// A run's errors come after its result, so they're filled in below.
		switch tr.Status {
		case "fail":
			c.Failure = &junitProblem{Message: "run " + tr.Run + " failed"}
			s.Failures++
		case "error":
			c.Error = &junitProblem{Message: "run " + tr.Run + " errored"}
			s.Errors++
		case "skip":
			c.Skipped = &struct{}{}
			s.Skipped++
		}
		s.Tests++
		s.Cases = append(s.Cases, c)
	}
	if err := sc.Err(); err != nil {
		return out, err
	}
	for _, name := range order {
		s := suites[name]
		var total time.Duration
		for i, c := range s.Cases {
			if p := cmp.Or(c.Failure, c.Error); p != nil {
				if msgs := errs[[2]string{name, c.Name}]; len(msgs) > 0 {
					p.Message, p.Text = msgs[0], strings.Join(msgs, "\n\n")
				}
			}
			s.Cases[i] = c
			d, _ := time.ParseDuration(c.Time + "s")
			total += d
		}
		s.Time = seconds(total)
		out.Tests += s.Tests
		out.Failures += s.Failures
		out.Errors += s.Errors
		out.Skipped += s.Skipped
		out.Suites = append(out.Suites, *s)
	}
	return out, nil
}

func seconds(d time.Duration) string {
	return fmt.Sprintf("%.3f", max(d, 0).Seconds())
}

func writeJUnit(path, stream string) error {
	in, err := os.Open(stream)
	if err != nil {
		return err
	}
	defer in.Close()
	suites, err := junitFrom(in)
	if err != nil {
		return err
	}
	b, err := xml.MarshalIndent(suites, "", "  ")
	if err != nil {
		return err
	}
	// Owner-only, like -report: a failure's errors can carry values.
	if err := os.WriteFile(path, append([]byte(xml.Header), append(b, '\n')...), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600) // a file already there keeps its mode otherwise
}
