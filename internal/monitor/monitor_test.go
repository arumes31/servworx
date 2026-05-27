package monitor

import (
	"fmt"
	"reflect"
	"testing"
	"net/http"
	"net/http/httptest"
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	success, msg := checkWebsite(server.URL, []int{200}, false)
	if !success {
		t.Errorf("expected success, got failure: %s", msg)
	}

	success, msg = checkWebsite(server.URL, []int{200}, true)
	if !success {
		t.Errorf("expected success with insecureSkip=true, got failure: %s", msg)
	}

	success, msg = checkWebsite(server.URL, []int{404}, false)
	if success {
		t.Errorf("expected failure for 404, got success: %s", msg)
	}
}

func TestCheckWebsiteInsecure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// This should fail because the server's certificate is self-signed and we're not skipping verification
	success, _ := checkWebsite(server.URL, []int{200}, false)
	if success {
		t.Error("expected failure for self-signed cert without insecureSkip")
	}

	// This should succeed because we're skipping verification
	success, msg := checkWebsite(server.URL, []int{200}, true)
	if !success {
		t.Errorf("expected success for self-signed cert with insecureSkip, got failure: %s", msg)
	}
}
