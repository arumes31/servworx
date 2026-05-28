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
				"container_names": "evil; $(whoami), bad|pipe"
			}
		]
	}`)
	os.WriteFile(cfgPath, cfgData, 0644)

	tests := []struct {
		name           string
		index          string
		mustNotContain string
	}{
		{
			name:           "Filtered malicious container, fallback to valid",
			index:          "0",
			mustNotContain: "data: No valid containers found",
		},
		{
			name:           "All containers malicious",
			index:          "1",
			mustNotContain: "NONE", // We expect "data: No valid containers found"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/logs/stream/"+tt.index, nil)
			// Mocking path value since it's used in parseIndex (mux.HandleFunc("GET /api/logs/stream/{index}"...))
			req.SetPathValue("index", tt.index)

			rr := httptest.NewRecorder()

			HandleAPILogsStreamGET(rr, req)

			body := rr.Body.String()
			if tt.index == "0" {
				if strings.Contains(body, "data: No valid containers found") {
					t.Errorf("Service 0 has valid 'valid-name', but got: %q", body)
				}
			} else {
				if !strings.Contains(body, "data: No valid containers found") {
					t.Errorf("Service 1 should have blocked all names, but got: %q", body)
				}
			}
		})
	}
}
