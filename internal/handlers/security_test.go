package handlers

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arumes31/servworx/internal/config"
)

func TestHandleAPILogsStreamGET_Security(t *testing.T) {
	// Setup temporary config
	tmpDir := t.TempDir()
	config.SetConfigDir(tmpDir)
	config.ClearCache()

	// Create config.json
	cfgPath := filepath.Join(tmpDir, "config.json")
	cfgData := []byte(`{
		"services": [
			{
				"name": "MixedService",
				"container_names": "bad name; touch /tmp/pwned, valid-name"
			},
			{
				"name": "PureMalicious",
				"container_names": "evil; jules, bad|pipe"
			},
			{
				"name": "HyphenName",
				"container_names": "-v, valid-name"
			}
		]
	}`)
	err := os.WriteFile(cfgPath, cfgData, 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	tests := []struct {
		name             string
		index            string
		expectAllBlocked bool
	}{
		{
			name:             "Filtered malicious container, fallback to valid",
			index:            "0",
			expectAllBlocked: false,
		},
		{
			name:             "All containers malicious",
			index:            "1",
			expectAllBlocked: true,
		},
		{
			name:            "Hyphen prefixed name allowed but safe",
			index:           "2",
			expectAllBlocked: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config.ClearCache()
			req := httptest.NewRequest("GET", "/api/logs/stream/"+tt.index, nil)
			// Mocking path value since it's used in parseIndex (mux.HandleFunc("GET /api/logs/stream/{index}"...))
			req.SetPathValue("index", tt.index)

			rr := httptest.NewRecorder()

			HandleAPILogsStreamGET(rr, req)

			body := rr.Body.String()
			if tt.expectAllBlocked {
				if !strings.Contains(body, "data: No valid containers found") {
					t.Errorf("expected all containers blocked, but got: %q", body)
				}
			} else {
				if strings.Contains(body, "data: No valid containers found") {
					t.Errorf("expected valid containers to remain, but got: %q", body)
				}
			}
		})
	}
}

func TestHandleViewLogsGET_Security(t *testing.T) {
	// Setup temporary config
	tmpDir := t.TempDir()
	config.SetConfigDir(tmpDir)

	// Create config.json
	cfgPath := filepath.Join(tmpDir, "config.json")
	cfgData := []byte(`{
		"services": [
			{
				"name": "MixedService",
				"container_names": "bad name; touch /tmp/pwned, valid-name"
			}
		]
	}`)
	err := os.WriteFile(cfgPath, cfgData, 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Create dummy status.json
	statusPath := filepath.Join(tmpDir, "status.json")
	statusData := []byte(`{"services": []}`)
	err = os.WriteFile(statusPath, statusData, 0644)
	if err != nil {
		t.Fatalf("Failed to write status file: %v", err)
	}

	// Init templates with a dummy template
	// Create dummy template file in a temp directory for the test
	tplDir := t.TempDir()
	err = os.WriteFile(filepath.Join(tplDir, "config.html"), []byte("<html><body>{{.Logs}}</body></html>"), 0644)
	if err != nil {
		t.Fatalf("Failed to write template file: %v", err)
	}
	InitTemplates(tplDir)

	req := httptest.NewRequest("GET", "/view_logs/0", nil)
	req.SetPathValue("index", "0")

	rr := httptest.NewRecorder()

	HandleViewLogsGET(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "Logs for bad name; touch /tmp/pwned: [Invalid container name]") {
		t.Errorf("expected malicious container to be blocked and logged as invalid, but got: %q", body)
	}
}
