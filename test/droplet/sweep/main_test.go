// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opentofu/opentofu/test/droplet/doapi"
)

func fakeAPI(t *testing.T, now time.Time) (*doapi.Client, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/droplets":
			if r.URL.Query().Get("tag_name") != doapi.Tag {
				t.Errorf("listed droplets without the tag filter: %s", r.URL)
			}
			fmt.Fprintf(w, `{"droplets":[
				{"id":1,"name":"conn3x-ci-old","created_at":%q},
				{"id":2,"name":"conn3x-ci-new","created_at":%q}]}`,
				now.Add(-3*time.Hour).Format(time.RFC3339), now.Add(-10*time.Minute).Format(time.RFC3339))
		case r.Method == http.MethodGet && r.URL.Path == "/account/keys":
			fmt.Fprint(w, `{"ssh_keys":[
				{"id":10,"name":"conn3x-ci-old"},
				{"id":11,"name":"conn3x-ci-new"},
				{"id":12,"name":"james-laptop"}]}`)
		case r.Method == http.MethodDelete:
			mu.Lock()
			deleted = append(deleted, r.URL.Path)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
		}
	}))
	t.Cleanup(srv.Close)
	return &doapi.Client{Token: "t", BaseURL: srv.URL}, func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := append([]string(nil), deleted...)
		sort.Strings(out)
		return out
	}
}

func TestSweepDeletesOnlyOldTaggedResources(t *testing.T) {
	now := time.Now()
	c, deleted := fakeAPI(t, now)
	if err := sweep(context.Background(), c, 2*time.Hour, false, now); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(deleted(), ","); got != "/account/keys/10,/droplets/1" {
		t.Fatalf("deleted %s, want only the old droplet and its key", got)
	}
}

func TestSweepDryRunDeletesNothing(t *testing.T) {
	now := time.Now()
	c, deleted := fakeAPI(t, now)
	if err := sweep(context.Background(), c, 2*time.Hour, true, now); err != nil {
		t.Fatal(err)
	}
	if got := deleted(); len(got) != 0 {
		t.Fatalf("dry run deleted %v", got)
	}
}
