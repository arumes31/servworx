package monitor

import (
	"strings"
	"io"
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/arumes31/servworx/internal/config"
)

// TestGetRestartFilename verifies the base64 encoded filename is deterministic
func TestGetRestartFilename(t *testing.T) {
	name := "my-service"
	filename1 := getRestartFilename(name)
	filename2 := getRestartFilename(name)
	if filename1 != filename2 {
		t.Errorf("expected deterministic filename, got different results: %s vs %s", filename1, filename2)
	}
	if filename1 == "" {
		t.Error("expected non-empty filename")
	}
	// Should contain the safe base64 representation
	if len(filename1) < len("last_restart_") {
		t.Errorf("filename too short: %s", filename1)
	}
}

// TestReadWriteLastRestart tests writing and reading the restart time from disk
func TestReadWriteLastRestart(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := config.ConfigDir
	config.SetConfigDir(tmpDir)
	t.Cleanup(func() { config.SetConfigDir(originalDir) })

	svcName := "restart-test-service"

	// Should return 0 when no file exists
	val := readLastRestart(svcName)
	if val != 0 {
		t.Errorf("expected 0 for missing file, got %d", val)
	}

	// Write a timestamp and read it back
	expectedTime := time.Now().Unix()
	writeLastRestart(svcName, expectedTime)

	gotTime := readLastRestart(svcName)
	if gotTime != expectedTime {
		t.Errorf("expected %d, got %d", expectedTime, gotTime)
	}
}

// TestReadLastRestartInvalidContent verifies graceful handling of corrupt data
func TestReadLastRestartInvalidContent(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := config.ConfigDir
	config.SetConfigDir(tmpDir)
	t.Cleanup(func() { config.SetConfigDir(originalDir) })

	svcName := "corrupt-service"
	filename := getRestartFilename(svcName)
	path := filepath.Join(tmpDir, filename)

	// Write invalid content
	if err := os.WriteFile(path, []byte("not-a-number"), 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	val := readLastRestart(svcName)
	if val != 0 {
		t.Errorf("expected 0 for invalid content, got %d", val)
	}
}

// TestLogActionAllTypes ensures LogAction doesn't panic for any log type
func TestLogActionAllTypes(t *testing.T) {
	logTypes := []string{"user", "system", "status", "error", "unknown"}
	for _, lt := range logTypes {
		// Should not panic
		LogAction("testuser", "test action", lt)
	}
	// Status type with Down/Up
	LogAction("System", "Service myservice status: Down", "status")
	LogAction("System", "Service myservice status: Up", "status")
}

// TestCheckWebsiteUnreachable verifies a closed server returns failure
func TestCheckWebsiteUnreachable(t *testing.T) {
	// Create and immediately close server to get a valid but unreachable URL
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := ts.URL
	ts.Close()

	success, msg := checkWebsite(url, []int{200}, false)
	if success {
		t.Errorf("expected failure for unreachable server, got success: %s", msg)
	}
}

// TestCheckWebsiteNonAcceptedStatusCode verifies rejection of non-accepted status
func TestCheckWebsiteNonAcceptedStatusCode(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	success, msg := checkWebsite(ts.URL, []int{200}, false)
	if success {
		t.Errorf("expected failure for 503, got success: %s", msg)
	}
	if msg == "" {
		t.Error("expected non-empty message")
	}
}

// TestCheckWebsite501Fallback covers the 501 fallback to GET path
func TestCheckWebsite501Fallback(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.WriteHeader(http.StatusNotImplemented) // 501
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	success, _ := checkWebsite(ts.URL, []int{200}, false)
	if !success {
		t.Error("expected success after GET fallback from 501")
	}
}

// TestCheckWebsiteGetFallbackUnreachable covers when GET after HEAD 405 also fails
func TestCheckWebsiteGetFallbackUnreachable(t *testing.T) {
	callCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.Method == "HEAD" {
			w.WriteHeader(http.StatusMethodNotAllowed) // 405
			return
		}
		// GET: return a non-accepted code
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	success, msg := checkWebsite(ts.URL, []int{200}, false)
	if success {
		t.Errorf("expected failure when GET also fails: %s", msg)
	}
}

// TestRestartContainersInvalidName verifies invalid container names are blocked
func TestRestartContainersInvalidName(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := config.ConfigDir
	config.SetConfigDir(tmpDir)
	t.Cleanup(func() { config.SetConfigDir(originalDir) })

	// Setup status
	svcName := "invalid-container-test"
	_ = config.UpdateStatus(func(s *config.Status) {
		s.Services = []config.ServiceStatus{
			{Name: svcName, Status: "Down", LastStableStatus: "Down"},
		}
	})

	// Should not panic, just log and skip invalid names
	result := restartContainers("bad name; rm -rf /", svcName)
	if result == 0 {
		t.Error("expected a non-zero last restart time even when all containers are invalid")
	}
}

// TestRestartContainersEmpty verifies empty container names are handled
func TestRestartContainersEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := config.ConfigDir
	config.SetConfigDir(tmpDir)
	t.Cleanup(func() { config.SetConfigDir(originalDir) })

	svcName := "empty-container-test"
	_ = config.UpdateStatus(func(s *config.Status) {
		s.Services = []config.ServiceStatus{
			{Name: svcName, Status: "Down", LastStableStatus: "Down"},
		}
	})

	// Empty string — should still return a valid timestamp
	result := restartContainers("", svcName)
	if result == 0 {
		t.Error("expected a non-zero last restart time even with empty container list")
	}
}

// TestCheckWithRetriesSuccess verifies checkWithRetries succeeds on the first attempt
func TestCheckWithRetriesSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := config.ConfigDir
	config.SetConfigDir(tmpDir)
	t.Cleanup(func() { config.SetConfigDir(originalDir) })

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	svcName := "retry-success-service"
	_ = config.UpdateStatus(func(s *config.Status) {
		s.Services = []config.ServiceStatus{
			{Name: svcName, Status: "Unknown", LastStableStatus: "Unknown"},
		}
	})

	svc := &config.ServiceConfig{
		Name:                svcName,
		WebsiteURL:          ts.URL,
		AcceptedStatusCodes: []int{200},
		Retries:             3,
		Interval:            1,
		InsecureSkipVerify:  false,
	}

	success, stopped := checkWithRetries(svc)
	if !success {
		t.Error("expected success from checkWithRetries")
	}
	if stopped {
		t.Error("expected stopped=false")
	}
}

// TestCheckWithRetriesAllFail verifies checkWithRetries exhausts all attempts
func TestCheckWithRetriesAllFail(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := config.ConfigDir
	config.SetConfigDir(tmpDir)
	t.Cleanup(func() { config.SetConfigDir(originalDir) })

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	svcName := "retry-all-fail-service"
	_ = config.UpdateStatus(func(s *config.Status) {
		s.Services = []config.ServiceStatus{
			{Name: svcName, Status: "Unknown", LastStableStatus: "Unknown"},
		}
	})

	svc := &config.ServiceConfig{
		Name:                svcName,
		WebsiteURL:          ts.URL,
		AcceptedStatusCodes: []int{200},
		Retries:             2,
		Interval:            1, // 1 second between retries
		InsecureSkipVerify:  false,
	}

	success, stopped := checkWithRetries(svc)
	if success {
		t.Error("expected failure from checkWithRetries")
	}
	if stopped {
		t.Error("expected stopped=false (not interrupted)")
	}
}

// TestStartStopMonitoring verifies monitoring can start and stop without deadlock
func TestStartStopMonitoring(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := config.ConfigDir
	config.SetConfigDir(tmpDir)
	t.Cleanup(func() { config.SetConfigDir(originalDir) })

	// Create a minimal config with no services
	cfg := &config.Config{
		Users:    map[string]string{"admin": "$2a$10$test"},
		Services: []config.ServiceConfig{},
	}
	_ = config.SaveConfig(cfg)

	// Should not panic or deadlock
	StartMonitoring()
	time.Sleep(50 * time.Millisecond)
	StopMonitoring()
}

// TestStartMonitoringNewService verifies a new service gets Unknown status
func TestStartMonitoringNewService(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := config.ConfigDir
	config.SetConfigDir(tmpDir)
	t.Cleanup(func() { config.SetConfigDir(originalDir) })

	svcName := fmt.Sprintf("new-service-%d", time.Now().UnixNano())
	cfg := &config.Config{
		Users: map[string]string{"admin": "$2a$10$test"},
		Services: []config.ServiceConfig{
			{
				Name:                svcName,
				WebsiteURL:          "http://127.0.0.1:19999", // Unreachable
				Retries:             1,
				Interval:            300, // Long interval so goroutine stays paused
				GracePeriod:         3600,
				AcceptedStatusCodes: []int{200},
			},
		},
	}
	_ = config.SaveConfig(cfg)
	_ = config.UpdateStatus(func(s *config.Status) {
		s.Services = []config.ServiceStatus{}
	})

	StartMonitoring()
	time.Sleep(100 * time.Millisecond)
	StopMonitoring()

	status, _ := config.LoadStatus()
	found := false
	for _, s := range status.Services {
		if s.Name == svcName {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected service %s to be initialized in status", svcName)
	}
}

// TestRestartMonitoring verifies RestartMonitoring doesn't panic
func TestRestartMonitoring(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := config.ConfigDir
	config.SetConfigDir(tmpDir)
	t.Cleanup(func() { config.SetConfigDir(originalDir) })

	cfg := &config.Config{
		Users:    map[string]string{"admin": "$2a$10$test"},
		Services: []config.ServiceConfig{},
	}
	_ = config.SaveConfig(cfg)

	// Should not panic
	StartMonitoring()
	RestartMonitoring()
	StopMonitoring()
}

// TestHandleServiceFailureWithRestart verifies the restart path runs without docker available
func TestHandleServiceFailureWithRestart(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := config.ConfigDir
	config.SetConfigDir(tmpDir)
	t.Cleanup(func() { config.SetConfigDir(originalDir) })

	svcName := "test-restart-svc"
	_ = config.UpdateStatus(func(s *config.Status) {
		s.Services = []config.ServiceStatus{
			{Name: svcName, Status: "Down", LastStableStatus: "Down"},
		}
	})

	svc := &config.ServiceConfig{
		Name:           svcName,
		ContainerNames: "", // empty — nothing to docker restart
	}

	newRestart := handleServiceFailure(svc, true, 0, 0)
	if newRestart == 0 {
		t.Error("expected non-zero restart timestamp")
	}
}

// TestUpdateServiceStatusChecking covers the "Checking" status branch
func TestUpdateServiceStatusChecking(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := config.ConfigDir
	config.SetConfigDir(tmpDir)
	t.Cleanup(func() { config.SetConfigDir(originalDir) })

	svcName := "checking-service"
	_ = config.UpdateStatus(func(s *config.Status) {
		s.Services = []config.ServiceStatus{
			{Name: svcName, Status: "Up", LastStableStatus: "Up"},
		}
	})

	updateServiceStatus(svcName, "Checking")

	status, _ := config.LoadStatus()
	if len(status.Services) == 0 {
		t.Fatal("expected at least one service in status")
	}
	if status.Services[0].Status != "Checking" {
		t.Errorf("expected status Checking, got %s", status.Services[0].Status)
	}
}

// TestUpdateServiceStatusUnknownToUp covers Unknown -> Up path
func TestUpdateServiceStatusUnknownToUp(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := config.ConfigDir
	config.SetConfigDir(tmpDir)
	t.Cleanup(func() { config.SetConfigDir(originalDir) })

	svcName := "unknown-to-up-service"
	_ = config.UpdateStatus(func(s *config.Status) {
		s.Services = []config.ServiceStatus{
			{Name: svcName, Status: "Unknown", LastStableStatus: "Unknown"},
		}
	})

	updateServiceStatus(svcName, "Up")

	status, _ := config.LoadStatus()
	if status.Services[0].Status != "Up" {
		t.Errorf("expected status Up, got %s", status.Services[0].Status)
	}
	if status.Services[0].UpSince == nil {
		t.Error("expected UpSince to be set on Unknown->Up transition")
	}
}

// TestUpdateServiceStatusRepeatDownNoRepeatInterval covers repeated Down with no interval configured
func TestUpdateServiceStatusRepeatDownNoRepeatInterval(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := config.ConfigDir
	config.SetConfigDir(tmpDir)
	t.Cleanup(func() { config.SetConfigDir(originalDir) })

	svcName := "no-repeat-svc"
	cfg := &config.Config{
		Services: []config.ServiceConfig{
			{
				Name:                svcName,
				AlertOnFailure:      true,
				AlertRepeatInterval: 0, // No repeat
			},
		},
	}
	_ = config.SaveConfig(cfg)

	_ = config.UpdateStatus(func(s *config.Status) {
		alertCount := 1
		lastTime := time.Now().Unix() - 60
		s.Services = []config.ServiceStatus{
			{
				Name:             svcName,
				Status:           "Down",
				LastStableStatus: "Down",
				AlertCount:       alertCount,
				LastAlertTime:    &lastTime,
			},
		}
	})

	// Should not send repeat alert (interval=0)
	updateServiceStatus(svcName, "Down")

	status, _ := config.LoadStatus()
	// AlertCount should remain unchanged (no repeat alerting)
	if status.Services[0].AlertCount != 1 {
		t.Errorf("expected AlertCount to remain 1, got %d", status.Services[0].AlertCount)
	}
}


func TestLogAction(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	LogAction("testuser", "test message", "user")

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "testuser") {
		t.Errorf("Expected output to contain 'testuser', got: %s", output)
	}
	if !strings.Contains(output, "test message") {
		t.Errorf("Expected output to contain 'test message', got: %s", output)
	}
	// Check for green color code
	if !strings.Contains(output, "\033[92m") {
		t.Errorf("Expected output to contain green color code, got: %s", output)
	}
}

func TestCheckWebsiteInsecure(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// This should succeed with insecureSkip=true
	success, msg := checkWebsite(ts.URL, []int{200}, true)
	if !success {
		t.Errorf("expected success with insecure skip, got failure: %s", msg)
	}
}

func TestCheckWebsiteGetError(t *testing.T) {
	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// Hijack connection and close it for GET
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("webserver doesn't support hijacking")
		}
		conn, _, _ := hj.Hijack()
		conn.Close()
	}))
	defer ts2.Close()

	success, msg := checkWebsite(ts2.URL, []int{200}, false)
	if success {
		t.Error("expected failure for GET error, got success")
	}
	if !strings.Contains(msg, "Website is unreachable") {
		t.Errorf("expected error message to contain 'Website is unreachable', got: %s", msg)
	}
}
