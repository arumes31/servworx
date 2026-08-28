package broker

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testToken = "0123456789abcdef0123456789abcdef"

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return fn(r)
}

func TestBrokerRestrictsAuthenticationAllowlistAndOperations(t *testing.T) {
	var dockerCalls int
	server := &Server{
		token:   testToken,
		allowed: map[string]struct{}{"web-1": {}},
		docker: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			dockerCalls++
			if r.Method != http.MethodPost || r.URL.Path != "/containers/web-1/restart" {
				t.Fatalf("unexpected Docker request: %s %s", r.Method, r.URL)
			}
			return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
		})},
	}

	for _, tc := range []struct {
		name   string
		path   string
		token  string
		status int
	}{
		{name: "missing token", path: "/v1/containers/web-1/restart", status: http.StatusUnauthorized},
		{name: "not allowlisted", path: "/v1/containers/db/restart", token: testToken, status: http.StatusForbidden},
		{name: "invalid name", path: "/v1/containers/-flag/restart", token: testToken, status: http.StatusBadRequest},
		{name: "allowed", path: "/v1/containers/web-1/restart", token: testToken, status: http.StatusNoContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.path, nil)
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			w := httptest.NewRecorder()
			server.Handler().ServeHTTP(w, req)
			if w.Code != tc.status {
				t.Fatalf("expected %d, got %d: %s", tc.status, w.Code, w.Body.String())
			}
		})
	}
	if dockerCalls != 1 {
		t.Fatalf("expected exactly one Docker API call, got %d", dockerCalls)
	}
}

func TestBrokerDemultiplexesBoundedDockerLogs(t *testing.T) {
	var frames bytes.Buffer
	header := make([]byte, 8)
	header[0] = 1
	binary.BigEndian.PutUint32(header[4:], uint32(len("hello\n")))
	frames.Write(header)
	frames.WriteString("hello\n")

	server := &Server{
		token:   testToken,
		allowed: map[string]struct{}{"web-1": {}},
		docker: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(frames.Bytes())),
				Header:     http.Header{"Content-Type": {"application/vnd.docker.raw-stream"}},
			}, nil
		})},
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/containers/web-1/logs?tail=10&follow=false", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Body.String() != "hello\n" {
		t.Fatalf("unexpected response %d %q", w.Code, w.Body.String())
	}
}
