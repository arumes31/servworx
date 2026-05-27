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

func TestCheckWebsite(t *testing.T) {
	tests := []struct {
		name           string
		handler        http.HandlerFunc
		acceptedCodes  []int
		insecureSkip   bool
		expectedResult bool
		expectedMsg    string
	}{
		{
			name: "Success HEAD 200",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			acceptedCodes:  []int{200},
			expectedResult: true,
			expectedMsg:    "status 200 (accepted)",
		},
		{
			name: "Not accepted code",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			acceptedCodes:  []int{200},
			expectedResult: false,
			expectedMsg:    "status 404 (not accepted)",
		},
		{
			name: "Fallback to GET on 405",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
				w.WriteHeader(http.StatusOK)
			},
			acceptedCodes:  []int{200},
			expectedResult: true,
			expectedMsg:    "status 200 (accepted)",
		},
		{
			name: "Fallback to GET on 501",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusNotImplemented)
					return
				}
				w.WriteHeader(http.StatusOK)
			},
			acceptedCodes:  []int{200},
			expectedResult: true,
			expectedMsg:    "status 200 (accepted)",
		},
		{
			name: "Accepted 404",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			acceptedCodes:  []int{404},
			expectedResult: true,
			expectedMsg:    "status 404 (accepted)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(tt.handler)
			defer ts.Close()

			gotResult, gotMsg := checkWebsite(ts.URL, tt.acceptedCodes, tt.insecureSkip)
			if gotResult != tt.expectedResult {
				t.Errorf("checkWebsite() gotResult = %v, want %v", gotResult, tt.expectedResult)
			}
			if !strings.Contains(strings.ToLower(gotMsg), strings.ToLower(tt.expectedMsg)) {
				t.Errorf("checkWebsite() gotMsg = %v, want to contain %v", gotMsg, tt.expectedMsg)
			}
		})
	}

	t.Run("Unreachable", func(t *testing.T) {
		gotResult, gotMsg := checkWebsite("http://localhost:12345", []int{200}, false)
		if gotResult != false {
			t.Errorf("expected false for unreachable URL, got true")
		}
		if !strings.Contains(gotMsg, "unreachable") {
			t.Errorf("expected error message to contain 'unreachable', got %s", gotMsg)
		}
	})

	t.Run("TLS Insecure Skip", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		// Should fail without insecure skip (httptest uses self-signed)
		gotResult, _ := checkWebsite(ts.URL, []int{200}, false)
		if gotResult != false {
			t.Errorf("expected false without insecure skip, got true")
		}

		// Should succeed with insecure skip
		gotResult, _ = checkWebsite(ts.URL, []int{200}, true)
		if gotResult != true {
			t.Errorf("expected true with insecure skip, got false")
		}
	})
}

func TestLogAction(t *testing.T) {
	tests := []struct {
		name          string
		logType       string
		username      string
		action        string
		expectedColor string
	}{
		{"User log", "user", "testuser", "logged in", colorGreen},
		{"System log", "system", "System", "started", colorBlue},
		{"Status Down log", "status", "Service", "Service Down", colorRed},
		{"Status Up log", "status", "Service", "Service Up", colorYellow},
		{"Error log", "error", "System", "failed", colorRed},
		{"Unknown log", "unknown", "User", "did something", colorReset},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Keep track of original stdout
			old := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			LogAction(tt.username, tt.action, tt.logType)

			w.Close()
			os.Stdout = old

			var buf strings.Builder
			_, _ = io.Copy(&buf, r)
			output := buf.String()

			if !strings.Contains(output, tt.username) {
				t.Errorf("expected output to contain username %s, got %s", tt.username, output)
			}
			if !strings.Contains(output, tt.action) {
				t.Errorf("expected output to contain action %s, got %s", tt.action, output)
			}
			if !strings.Contains(output, tt.expectedColor) {
				t.Errorf("expected output to contain color code %q, got %q", tt.expectedColor, output)
			}
		})
	}
}
