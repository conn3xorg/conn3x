// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

func TestDecodeTextRoundTrips(t *testing.T) {
	utf16le := func(s string) []byte {
		out := []byte{0xFF, 0xFE}
		for _, r := range s {
			out = append(out, byte(r), byte(r>>8))
		}
		return out
	}
	for name, c := range map[string]struct {
		in   []byte
		enc  Encoding
		crlf bool
		text string
	}{
		"utf-8, LF":            {[]byte("a=1\nb=2\n"), UTF8, false, "a=1\nb=2\n"},
		"utf-8, CRLF":          {[]byte("a=1\r\nb=2\r\n"), UTF8, true, "a=1\nb=2\n"},
		"utf-8 with BOM":       {append([]byte{0xEF, 0xBB, 0xBF}, "é=1\r\n"...), UTF8BOM, true, "é=1\n"},
		"utf-16 LE, CRLF":      {utf16le("key=valué\r\nx=y\r\n"), UTF16LEBOM, true, "key=valué\nx=y\n"},
		"no final line ending": {[]byte("a=1\r\nb=2"), UTF8, true, "a=1\nb=2"},
		"empty":                {[]byte{}, UTF8, false, ""},
	} {
		f, err := DecodeText(c.in)
		if err != nil || f.Encoding != c.enc || f.CRLF != c.crlf || f.Text != c.text || !f.Exists {
			t.Errorf("%s: %+v, %v", name, f, err)
			continue
		}
		// Unchanged text writes back the same bytes.
		if got := f.Encode(); !bytes.Equal(got, c.in) {
			t.Errorf("%s: wrote back %q, from %q", name, got, c.in)
		}
	}
	// An edit to a UTF-16 CRLF file stays UTF-16 and CRLF.
	f, _ := DecodeText(utf16le("a=1\r\n"))
	f.Text += "b=2\n"
	if got, want := f.Encode(), utf16le("a=1\r\nb=2\r\n"); !bytes.Equal(got, want) {
		t.Errorf("edited UTF-16: %x, want %x", got, want)
	}
	if got := NewTextFile(); got.Encoding != UTF8 || !got.CRLF || got.Exists {
		t.Errorf("a new file: %+v", got)
	}
	for want, in := range map[string][]byte{
		"big-endian":       {0xFE, 0xFF, 0, 'a'},
		"isn't UTF-8":      {'a', 0xE9, 'b'},
		"odd number":       {0xFF, 0xFE, 'a'},
		"NUL":              []byte("a\x00b"),
		"byte order mark ": {0xEF, 0xBB, 0xBF, 0xFF},
		"mixes":            []byte("a=1\r\nb=2\nc=3\r\n"),
		"without its pair": {0xFF, 0xFE, 0x00, 0xD8, 'a', 0},
	} {
		if _, err := DecodeText(in); err == nil || !strings.Contains(err.Error(), strings.TrimSpace(want)) {
			t.Errorf("%x: %v, want %q", in, err, want)
		}
	}
}

func TestReadTextFile(t *testing.T) {
	ctx := context.Background()
	f := &fake{answers: []map[string]any{ok(map[string]any{"ok": true, "exists": false})}}
	if tf, err := ReadTextFile(ctx, f, `C:\x.ini`); err != nil || tf.Exists || args(f, 0)["max"] != float64(MaxContent) {
		t.Errorf("missing: %+v %v %v", tf, err, f.sent)
	}
	f = &fake{answers: []map[string]any{ok(map[string]any{"ok": true, "exists": true, "content": base64.StdEncoding.EncodeToString([]byte("a=1\r\n"))})}}
	if tf, err := ReadTextFile(ctx, f, `C:\x.ini`); err != nil || !tf.Exists || tf.Text != "a=1\n" || !tf.CRLF {
		t.Errorf("a file: %+v %v", tf, err)
	}
	f = &fake{answers: []map[string]any{ok(map[string]any{"ok": false, "why": "it is a link"})}}
	if _, err := ReadTextFile(ctx, f, `C:\x.ini`); err == nil || err.Error() != `C:\x.ini can't be edited: it is a link` {
		t.Errorf("a link: %v", err)
	}
	f = &fake{answers: []map[string]any{ok(map[string]any{"ok": true, "exists": true, "content": base64.StdEncoding.EncodeToString([]byte{0xFE, 0xFF, 0, 'a'})})}}
	if _, err := ReadTextFile(ctx, f, `C:\x.ini`); err == nil || !strings.Contains(err.Error(), "big-endian") {
		t.Errorf("big-endian: %v", err)
	}
}
