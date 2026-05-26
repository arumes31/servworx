package monitor

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
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
	// Mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" || r.Method == "GET" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer server.Close()

	// Test case 1: Success with default client
	success, message := checkWebsite(server.URL, []int{200}, false)
	if !success {
		t.Errorf("expected success, got failure: %s", message)
	}

	// Test case 2: Success with insecure client (though mock server is HTTP)
	success, message = checkWebsite(server.URL, []int{200}, true)
	if !success {
		t.Errorf("expected success with insecureSkip=true, got failure: %s", message)
	}

	// Test case 3: Failure with wrong status code
	success, message = checkWebsite(server.URL, []int{201}, false)
	if success {
		t.Errorf("expected failure for status 201, got success: %s", message)
	}

	// Test case 4: Fallback from HEAD to GET
	serverFallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.WriteHeader(http.StatusMethodNotAllowed) // 405
			return
		}
		if r.Method == "GET" {
			w.WriteHeader(http.StatusOK)
			return
		}
	}))
	defer serverFallback.Close()

	success, message = checkWebsite(serverFallback.URL, []int{200}, false)
	if !success {
		t.Errorf("expected success with fallback to GET, got failure: %s", message)
	}
}
