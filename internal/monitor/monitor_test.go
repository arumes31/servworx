package monitor

import (
	"fmt"
	"github.com/arumes31/servworx/internal/config"
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

func TestUpdateServiceStatus(t *testing.T) {
	serviceName := "test-service"
	_ = config.UpdateStatus(func(s *config.Status) {
		s.Services = []config.ServiceStatus{
			{Name: serviceName, Status: "Down", LastStableStatus: "Down"},
		}
	})

	// Test transition Down -> Up
	updateServiceStatus(serviceName, "Up")
	status, _ := config.LoadStatus()
	if status.Services[0].Status != "Up" {
		t.Errorf("expected status Up, got %s", status.Services[0].Status)
	}
	if status.Services[0].UpSince == nil {
		t.Error("expected UpSince to be set")
	}

	// Test transition Up -> Down
	updateServiceStatus(serviceName, "Down")
	status, _ = config.LoadStatus()
	if status.Services[0].Status != "Down" {
		t.Errorf("expected status Down, got %s", status.Services[0].Status)
	}
	if status.Services[0].DownSince == nil {
		t.Error("expected DownSince to be set")
	}
	if status.Services[0].UpSince != nil {
		t.Error("expected UpSince to be cleared")
	}
}

func TestHandleServiceFailure(t *testing.T) {
	svc := &config.ServiceConfig{
		Name:           "test-service",
		ContainerNames: "", // avoid actual docker calls if possible
	}

	// Test failure without restart (grace period active)
	lastRestart := int64(100)
	remainingGrace := int64(50)
	newRestart := handleServiceFailure(svc, false, remainingGrace, lastRestart)

	if newRestart != lastRestart {
		t.Errorf("expected lastRestart %d to be unchanged, got %d", lastRestart, newRestart)
	}
}
