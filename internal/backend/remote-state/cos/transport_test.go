// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package cos

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLogRoundTripperOmitsResponseBody(t *testing.T) {
	const secret = "TmpSecretKey-must-not-be-logged"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"Response":{"Credentials":{"TmpSecretKey":"`+secret+`"}}}`)
	}))
	defer srv.Close()

	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(prev)

	req, err := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(`{"RoleArn":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&LogRoundTripper{}).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)

	if !strings.Contains(string(body), secret) {
		t.Fatalf("caller lost the response body: %q", body)
	}
	if strings.Contains(logs.String(), secret) {
		t.Fatalf("response body was logged: %q", logs.String())
	}
}
