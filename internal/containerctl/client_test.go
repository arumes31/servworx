package containerctl

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testToken = "0123456789abcdef0123456789abcdef"

func TestClientAuthenticatesAndConstrainsRequests(t *testing.T) {
	t.Parallel()
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if !Authorized(r.Header.Get("Authorization"), testToken) {
			t.Error("request was not authenticated")
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/containers/web-1/restart":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/containers/web-1/logs":
			_, _ = io.WriteString(w, "safe logs")
		default:
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	client, err := New(server.URL, testToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Restart(context.Background(), "web-1"); err != nil {
		t.Fatal(err)
	}
	logs, err := client.Logs(context.Background(), "web-1", 10, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logs.Close() }()
	if body, _ := io.ReadAll(logs); string(body) != "safe logs" {
		t.Fatalf("unexpected logs: %q", body)
	}
	if requests != 2 {
		t.Fatalf("expected 2 requests, got %d", requests)
	}
}

func TestClientRejectsInvalidConfigurationAndNames(t *testing.T) {
	t.Parallel()
	for _, rawURL := range []string{"", "unix:///var/run/docker.sock", "http://user@example.test", "http://example.test?x=1"} {
		if _, err := New(rawURL, testToken); err == nil {
			t.Errorf("expected URL %q to fail", rawURL)
		}
	}
	if _, err := New("http://broker", "short"); err == nil {
		t.Error("expected short token to fail")
	}
	client, err := New("http://broker", testToken)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "-flag", "../escape", "bad/name", "bad name"} {
		if err := client.Restart(context.Background(), name); err == nil || !strings.Contains(err.Error(), "invalid") {
			t.Errorf("expected invalid name %q to fail, got %v", name, err)
		}
	}
}
