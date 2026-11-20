// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
)

// Encoding is how a text file's bytes hold its text.
type Encoding int

const (
	UTF8       Encoding = iota // no byte order mark
	UTF8BOM                    // EF BB BF first
	UTF16LEBOM                 // FF FE first, as Notepad's "Unicode" writes it
)

var (
	bomUTF8    = []byte{0xEF, 0xBB, 0xBF}
	bomUTF16LE = []byte{0xFF, 0xFE}
	bomUTF16BE = []byte{0xFE, 0xFF}
)

// TextFile is a text file's text, with "\n" line endings whatever it has,
// and how to write it back as it was.
type TextFile struct {
	Exists   bool
	Text     string
	Encoding Encoding
	CRLF     bool // the file's lines end in "\r\n"
}

// NewTextFile is what a file an edit creates starts as: empty, UTF-8 with
// no byte order mark and "\r\n" line endings, as Notepad and Ansible's
// win_lineinfile make new files.
func NewTextFile() TextFile { return TextFile{CRLF: true} }

// DecodeText reads b as a text file: UTF-8, with or without a byte order
// mark, or UTF-16 LE with one. Its line endings are "\r\n" if it has any,
// or none at all, and each is read as "\n". Anything else is refused, not
// guessed at.
func DecodeText(b []byte) (TextFile, error) {
	f := TextFile{Exists: true}
	orig := b
	var s string
	switch {
	case bytes.HasPrefix(b, bomUTF8):
		f.Encoding, b = UTF8BOM, b[len(bomUTF8):]
		if !utf8.Valid(b) {
			return TextFile{}, errors.New("it starts with a UTF-8 byte order mark but isn't UTF-8")
		}
		s = string(b)
	case bytes.HasPrefix(b, bomUTF16LE):
		f.Encoding, b = UTF16LEBOM, b[len(bomUTF16LE):]
		if len(b)%2 != 0 {
			return TextFile{}, errors.New("it starts with a UTF-16 LE byte order mark but has an odd number of bytes")
		}
		u := make([]uint16, len(b)/2)
		for i := range u {
			u[i] = binary.LittleEndian.Uint16(b[2*i:])
		}
		s = string(utf16.Decode(u))
	case bytes.HasPrefix(b, bomUTF16BE):
		return TextFile{}, errors.New("it's UTF-16 big-endian, which windows_line doesn't write")
	default:
		if !utf8.Valid(b) {
			return TextFile{}, errors.New("it isn't UTF-8 or UTF-16 LE text with a byte order mark; another code page would be guessed at, so it isn't edited")
		}
		s = string(b)
	}
	if strings.ContainsRune(s, 0) {
		return TextFile{}, errors.New("it has a NUL, so it isn't text")
	}
	// A file with no line ending yet gets \r\n, as a file create makes
	// does, and as Windows tools expect.
	f.CRLF = strings.Contains(s, "\r\n") || !strings.Contains(s, "\n")
	f.Text = strings.ReplaceAll(s, "\r\n", "\n")
	// What's read has to write back as it was, or an edit would change lines
	// it never meant to touch.
	if !bytes.Equal(f.Encode(), orig) {
		crlf := strings.Count(s, "\r\n")
		switch {
		case strings.Count(s, "\r") != crlf:
			return TextFile{}, errors.New("it has a carriage return that isn't part of a line ending, which wouldn't be written back as it was")
		case crlf > 0 && strings.Count(s, "\n") != crlf:
			return TextFile{}, errors.New("it mixes \\r\\n and \\n line endings, which wouldn't be written back as they were; give it one kind first")
		case f.Encoding == UTF16LEBOM:
			return TextFile{}, errors.New("it has a UTF-16 surrogate without its pair, which wouldn't be written back as it was")
		}
		return TextFile{}, errors.New("it wouldn't be written back as it was")
	}
	return f, nil
}

// Encode is f's text as its file holds it.
func (f TextFile) Encode() []byte {
	s := f.Text
	if f.CRLF {
		s = strings.ReplaceAll(s, "\n", "\r\n")
	}
	switch f.Encoding {
	case UTF8BOM:
		return append(append([]byte{}, bomUTF8...), s...)
	case UTF16LEBOM:
		u := utf16.Encode([]rune(s))
		out := make([]byte, len(bomUTF16LE)+2*len(u))
		copy(out, bomUTF16LE)
		for i, c := range u {
			binary.LittleEndian.PutUint16(out[len(bomUTF16LE)+2*i:], c)
		}
		return out
	}
	return []byte(s)
}

// ReadTextFile reads a text file for an edit step. A missing file has
// Exists false; a link, a folder, a file over MaxContent or one that isn't
// text is an error.
func ReadTextFile(ctx context.Context, r ps.Runner, path string) (TextFile, error) {
	res, err := ps.Read(ctx, r, script("read_text_file.ps1"), map[string]any{"path": path, "max": MaxContent})
	if err != nil {
		return TextFile{}, err
	}
	var a struct {
		OK      bool   `json:"ok"`
		Exists  bool   `json:"exists"`
		Why     string `json:"why"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(res.Value, &a); err != nil {
		return TextFile{}, fmt.Errorf("reading %s: %w", path, err)
	}
	if !a.OK {
		return TextFile{}, fmt.Errorf("%s can't be edited: %s", path, a.Why)
	}
	if !a.Exists {
		return TextFile{}, nil
	}
	b, err := base64.StdEncoding.DecodeString(a.Content)
	if err != nil {
		return TextFile{}, fmt.Errorf("reading %s: %w", path, err)
	}
	f, err := DecodeText(b)
	if err != nil {
		return TextFile{}, fmt.Errorf("%s can't be edited: %w", path, err)
	}
	return f, nil
}
