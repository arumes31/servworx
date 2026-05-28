package monitor

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestGetHistoryEmpty(t *testing.T) {
	historyMutex.Lock()
	healthHistory = make(map[string][]string)
	historyMutex.Unlock()

	history := GetHistory("non-existent")
	if len(history) != 0 {
		t.Errorf("expected empty history, got %v", history)
	}
}

func TestPushAndGetHistory(t *testing.T) {
	historyMutex.Lock()
	healthHistory = make(map[string][]string)
	historyMutex.Unlock()

	serviceName := "service1"
	PushHistory(serviceName, "Up")
	PushHistory(serviceName, "Down")

	expected := []string{"Up", "Down"}
	history := GetHistory(serviceName)

	if !reflect.DeepEqual(history, expected) {
		t.Errorf("expected %v, got %v", expected, history)
	}
}

func TestPushHistoryLimit(t *testing.T) {
	historyMutex.Lock()
	healthHistory = make(map[string][]string)
	historyMutex.Unlock()

	serviceName := "service1"
	for i := 1; i <= 31; i++ {
		PushHistory(serviceName, fmt.Sprintf("Status %d", i))
	}

	history := GetHistory(serviceName)
	if len(history) != 30 {
		t.Errorf("expected history length 30, got %d", len(history))
	}

	if history[0] != "Status 2" {
		t.Errorf("expected first element Status 2, got %s", history[0])
	}

	if history[29] != "Status 31" {
		t.Errorf("expected last element Status 31, got %s", history[29])
	}
}

func TestGetHistoryCopy(t *testing.T) {
	historyMutex.Lock()
	healthHistory = make(map[string][]string)
	historyMutex.Unlock()

	serviceName := "service1"
	PushHistory(serviceName, "Up")

	history := GetHistory(serviceName)
	if len(history) != 1 {
		t.Fatalf("expected history length 1, got %d", len(history))
	}

	// Modify the returned slice
	history[0] = "Modified"

	// Get history again and verify it hasn't changed internally
	newHistory := GetHistory(serviceName)
	if newHistory[0] != "Up" {
		t.Errorf("expected history to remain 'Up', but got '%s'", newHistory[0])
	}
}

func TestLogAction(t *testing.T) {
	tests := []struct {
		name     string
		username string
		action   string
		logType  string
		expected string // partial match for color and content
	}{
		{"User log", "alice", "logged in", "user", "\033[92m"},
		{"System log", "System", "restarted", "system", "\033[94m"},
		{"Status Up log", "System", "Service Up", "status", "\033[93m"},
		{"Status Down log", "System", "Service Down", "status", "\033[91m"},
		{"Error log", "System", "failed", "error", "\033[91m"},
		{"Unknown log", "bob", "clicked", "unknown", "\033[0m"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, w, _ := os.Pipe()
			oldStdout := os.Stdout
			os.Stdout = w

			LogAction(tt.username, tt.action, tt.logType)

			w.Close()
			os.Stdout = oldStdout

			var buf strings.Builder
			_, _ = io.Copy(&buf, r)
			output := buf.String()

			if !strings.Contains(output, tt.expected) {
				t.Errorf("expected output to contain color %q, got %q", tt.expected, output)
			}
			if !strings.Contains(output, tt.username) {
				t.Errorf("expected output to contain username %q, got %q", tt.username, output)
			}
			if !strings.Contains(output, tt.action) {
				t.Errorf("expected output to contain action %q, got %q", tt.action, output)
			}
		})
	}
}

func TestCheckWebsite(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			if r.URL.Path == "/405" {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			if r.URL.Path == "/501" {
				w.WriteHeader(http.StatusNotImplemented)
				return
			}
			if r.URL.Path == "/404" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == http.MethodGet {
			if r.URL.Path == "/405" || r.URL.Path == "/501" {
				w.WriteHeader(http.StatusOK)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	tlsTs := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer tlsTs.Close()

	tests := []struct {
		name          string
		url           string
		acceptedCodes []int
		insecureSkip  bool
		wantSuccess   bool
	}{
		{"Success 200 HEAD", ts.URL, []int{200}, false, true},
		{"Failure 404", ts.URL + "/404", []int{200}, false, false},
		{"Fallback GET 405", ts.URL + "/405", []int{200}, false, true},
		{"Fallback GET 501", ts.URL + "/501", []int{200}, false, true},
		{"Insecure Skip Verify", tlsTs.URL, []int{200}, true, true},
		{"Insecure Fail Verify", tlsTs.URL, []int{200}, false, false},
		{"Unreachable", "http://localhost:1", []int{200}, false, false},
		{"Accepted 404", ts.URL + "/404", []int{404}, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			success, msg := checkWebsite(tt.url, tt.acceptedCodes, tt.insecureSkip)
			if success != tt.wantSuccess {
				t.Errorf("checkWebsite(%q) success = %v, want %v. Message: %s", tt.url, success, tt.wantSuccess, msg)
			}
		})
	}
}
