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
		wantCont []string
	}{
		{"user", "Alice", "logged in", "user", []string{colorGreen, "Alice: logged in", colorReset}},
		{"system", "System", "startup", "system", []string{colorBlue, "System: startup", colorReset}},
		{"status up", "System", "Service is Up", "status", []string{colorYellow, "System: Service is Up", colorReset}},
		{"status down", "System", "Service is Down", "status", []string{colorRed, "System: Service is Down", colorReset}},
		{"error", "System", "Critical error", "error", []string{colorRed, "System: Critical error", colorReset}},
		{"default", "Alice", "did something", "unknown", []string{colorReset, "Alice: did something", colorReset}},
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
			got := buf.String()

			for _, want := range tt.wantCont {
				if !strings.Contains(got, want) {
					t.Errorf("LogAction() output = %q, want to contain %q", got, want)
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
		wantSuccess   bool
		wantMessage   string
	}{
		{
			name: "Success HEAD 200",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			acceptedCodes: []int{200},
			wantSuccess:   true,
			wantMessage:   "Website returned status 200 (accepted)",
		},
		{
			name: "Failure HEAD 404",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			acceptedCodes: []int{200},
			wantSuccess:   false,
			wantMessage:   "Website returned status 404 (not accepted)",
		},
		{
			name: "Fallback 405 to GET 200",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
				w.WriteHeader(http.StatusOK)
			},
			acceptedCodes: []int{200},
			wantSuccess:   true,
			wantMessage:   "Website returned status 200 (accepted)",
		},
		{
			name: "Fallback 501 to GET 200",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusNotImplemented)
					return
				}
				w.WriteHeader(http.StatusOK)
			},
			acceptedCodes: []int{200},
			wantSuccess:   true,
			wantMessage:   "Website returned status 200 (accepted)",
		},
		{
			name: "Fallback 405 to GET 404 failure",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			},
			acceptedCodes: []int{200},
			wantSuccess:   false,
			wantMessage:   "Website returned status 404 (not accepted)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			gotSuccess, gotMessage := checkWebsite(server.URL, tt.acceptedCodes, true)
			if gotSuccess != tt.wantSuccess {
				t.Errorf("checkWebsite() success = %v, want %v", gotSuccess, tt.wantSuccess)
			}
			if !strings.Contains(gotMessage, tt.wantMessage) {
				t.Errorf("checkWebsite() message = %q, want to contain %q", gotMessage, tt.wantMessage)
			}
		})
	}

	t.Run("Unreachable URL", func(t *testing.T) {
		gotSuccess, gotMessage := checkWebsite("http://localhost:12345", []int{200}, true)
		if gotSuccess != false {
			t.Errorf("checkWebsite() success = %v, want false", gotSuccess)
		}
		if !strings.Contains(gotMessage, "Website is unreachable") {
			t.Errorf("checkWebsite() message = %q, want to contain 'Website is unreachable'", gotMessage)
		}
	})
}
