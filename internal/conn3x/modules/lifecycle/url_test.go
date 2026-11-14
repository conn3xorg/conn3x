// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package lifecycle

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// dialer stands in for the SSH connection: it dials from here, and counts.
type dialer struct{ dials atomic.Int32 }

func (d *dialer) Run(context.Context, string, []byte) (ssh.Result, error) {
	return ssh.Result{}, nil
}

func (d *dialer) DialRemote(ctx context.Context, addr string) (net.Conn, error) {
	d.dials.Add(1)
	return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
}

func TestURLCheck(t *testing.T) {
	var up atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()
	d := &dialer{}
	w := WaitFor{URL: URLCheck{URL: srv.URL + "/healthz", BodyContains: `"ok"`}, Timeout: 5 * time.Second}
	if err := w.Validate(); err != nil {
		t.Fatal(err)
	}
	if ok, err := w.Ready(context.Background(), d); ok || err != nil {
		t.Fatalf("ready while down: %v, %v", ok, err)
	}
	time.AfterFunc(1500*time.Millisecond, func() { up.Store(true) })
	if err := w.Wait(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if d.dials.Load() < 2 {
		t.Errorf("dialled %d times, not through the host", d.dials.Load())
	}

	// The wrong answer times out and says what it got.
	w = WaitFor{URL: URLCheck{URL: srv.URL, StatusCodes: []int{204}}, Timeout: time.Second}
	if err := w.Wait(context.Background(), d); err == nil || !strings.Contains(err.Error(), "answered 200 OK, not 204") {
		t.Errorf("wrong status: %v", err)
	}
	w = WaitFor{URL: URLCheck{URL: srv.URL, BodyContains: "nope"}, Timeout: time.Second}
	if err := w.Wait(context.Background(), d); err == nil || !strings.Contains(err.Error(), `doesn't hold "nope"`) {
		t.Errorf("wrong body: %v", err)
	}

	// A runner that can't dial from the host is an error, not a wait.
	if _, err := (WaitFor{URL: URLCheck{URL: srv.URL}}).Ready(context.Background(), noDial{}); err == nil {
		t.Error("no dialer accepted")
	}

	for _, bad := range []WaitFor{
		{URL: URLCheck{URL: "ftp://x/"}},
		{URL: URLCheck{URL: "http://"}},
		{URL: URLCheck{URL: "http://u:p@x/"}},
		{URL: URLCheck{URL: "http://x/", StatusCodes: []int{99}}},
		{URL: URLCheck{URL: "http://x/"}, Port: 80},
	} {
		if bad.Validate() == nil {
			t.Errorf("%+v passed", bad)
		}
	}
}

type noDial struct{}

func (noDial) Run(context.Context, string, []byte) (ssh.Result, error) { return ssh.Result{}, nil }

func TestDo(t *testing.T) {
	var got struct{ method, auth, body string }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.method, got.auth, got.body = r.Method, r.Header.Get("Authorization"), string(b)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":7}`))
	}))
	defer srv.Close()
	d := &dialer{}
	req := Request{URLCheck: URLCheck{URL: srv.URL + "/hosts", StatusCodes: []int{201}}, Method: "POST", Headers: map[string]string{"Authorization": "Bearer t"}, Body: `{"host":"web1"}`}
	res, err := Do(context.Background(), d, req)
	if err != nil || res.Status != 201 || res.Body != `{"id":7}` {
		t.Fatalf("res = %+v, %v", res, err)
	}
	if got.method != "POST" || got.auth != "Bearer t" || got.body != `{"host":"web1"}` || d.dials.Load() != 1 {
		t.Errorf("server saw %+v, %d dials", got, d.dials.Load())
	}
	req.StatusCodes = nil
	if _, err := Do(context.Background(), d, req); err == nil || !strings.Contains(err.Error(), "answered 201 Created, not 200") {
		t.Errorf("an unexpected status: %v", err)
	}
}
