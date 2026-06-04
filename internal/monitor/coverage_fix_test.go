package monitor

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestLogActionVerification(t *testing.T) {
	r, w, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	// Capture LogAction output
	LogAction("testuser", "Service is Down", "status")
	LogAction("testuser", "Service is Up", "status")
	LogAction("testuser", "User action", "user")
	LogAction("testuser", "System action", "system")
	LogAction("testuser", "Error occurred", "error")

	w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	// Verify colors (assuming color variables are accessible in the same package)
	if !strings.Contains(output, colorRed) {
		t.Error("expected red color for Down status or error log")
	}
	if !strings.Contains(output, colorYellow) {
		t.Error("expected yellow color for Up status log")
	}
	if !strings.Contains(output, colorGreen) {
		t.Error("expected green color for user log")
	}
	if !strings.Contains(output, colorBlue) {
		t.Error("expected blue color for system log")
	}

	// Verify content
	if !strings.Contains(output, "testuser") || !strings.Contains(output, "Service is Down") {
		t.Error("output missing expected username or action text")
	}
}

func TestCheckWebsiteGetError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			// Trigger fallback to GET
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.Method == "GET" {
			// Simulate a network error during GET
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("webserver doesn't support hijacking")
			}
			conn, _, _ := hj.Hijack()
			conn.Close()
			return
		}
	}))
	defer ts.Close()

	success, msg := checkWebsite(ts.URL, []int{200}, false)
	if success {
		t.Error("expected failure on GET network error, but got success")
	}
	if !strings.Contains(msg, "Website is unreachable") {
		t.Errorf("expected 'Website is unreachable' in error message, got: %s", msg)
	}
}
