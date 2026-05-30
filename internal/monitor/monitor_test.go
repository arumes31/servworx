package monitor

import (
	"bytes"
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
		expected []string // substrings expected in output
	}{
		{
			name:     "user log",
			username: "Alice",
			action:   "logged in",
			logType:  "user",
			expected: []string{colorGreen, "Alice", "logged in"},
		},
		{
			name:     "system log",
			username: "System",
			action:   "started",
			logType:  "system",
			expected: []string{colorBlue, "System", "started"},
		},
		{
			name:     "status log up",
			username: "System",
			action:   "Service Up",
			logType:  "status",
			expected: []string{colorYellow, "System", "Service Up"},
		},
		{
			name:     "status log down",
			username: "System",
			action:   "Service Down",
			logType:  "status",
			expected: []string{colorRed, "System", "Service Down"},
		},
		{
			name:     "error log",
			username: "System",
			action:   "failed",
			logType:  "error",
			expected: []string{colorRed, "System", "failed"},
		},
		{
			name:     "unknown log",
			username: "System",
			action:   "something",
			logType:  "unknown",
			expected: []string{colorReset, "System", "something"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			old := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			LogAction(tt.username, tt.action, tt.logType)

			w.Close()
			os.Stdout = old

			var buf bytes.Buffer
			_, _ = io.Copy(&buf, r)
			output := buf.String()

			for _, exp := range tt.expected {
				if !strings.Contains(output, exp) {
					t.Errorf("expected output to contain %q, but got %q", exp, output)
				}
			}
		})
	}
}

func TestCheckWebsite(t *testing.T) {
	tests := []struct {
		name          string
		handler       http.HandlerFunc
		acceptedCodes []int
		expectedSuccess bool
	}{
		{
			name: "successful HEAD",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			acceptedCodes: []int{200},
			expectedSuccess: true,
		},
		{
			name: "HEAD 405 fallback to GET success",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
				w.WriteHeader(http.StatusOK)
			},
			acceptedCodes: []int{200},
			expectedSuccess: true,
		},
		{
			name: "HEAD 501 fallback to GET success",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusNotImplemented)
					return
				}
				w.WriteHeader(http.StatusOK)
			},
			acceptedCodes: []int{200},
			expectedSuccess: true,
		},
		{
			name: "unaccepted status code",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			acceptedCodes: []int{200},
			expectedSuccess: false,
		},
		{
			name: "accepted non-200 code",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			acceptedCodes: []int{404},
			expectedSuccess: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			success, msg := checkWebsite(server.URL, tt.acceptedCodes, false)
			if success != tt.expectedSuccess {
				t.Errorf("expected success %v, got %v (message: %s)", tt.expectedSuccess, success, msg)
			}
		})
	}

	t.Run("unreachable URL", func(t *testing.T) {
		success, _ := checkWebsite("http://localhost:1", []int{200}, false)
		if success {
			t.Error("expected failure for unreachable URL, but got success")
		}
	})

	t.Run("GET fallback failure", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			// Force close connection for GET
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("webserver doesn't support hijacking")
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Fatalf("hijack failed: %v", err)
			}
			conn.Close()
		}))
		defer server.Close()

		success, msg := checkWebsite(server.URL, []int{200}, false)
		if success {
			t.Errorf("expected failure for GET fallback failure, but got success")
		}
		if !strings.Contains(msg, "unreachable") {
			t.Errorf("expected error message to contain 'unreachable', got %q", msg)
		}
	})
}

func TestCheckWebsiteInsecure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Test with InsecureSkipVerify = true
	success, msg := checkWebsite(server.URL, []int{200}, true)
	if !success {
		t.Errorf("expected success with InsecureSkipVerify=true, but failed: %s", msg)
	}

	// Test with InsecureSkipVerify = false (should fail due to self-signed cert)
	success, msg = checkWebsite(server.URL, []int{200}, false)
	if success {
		t.Error("expected failure with InsecureSkipVerify=false for self-signed cert, but got success")
	}
}
