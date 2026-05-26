package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/arumes31/servworx/internal/auth"
	"github.com/arumes31/servworx/internal/config"
)

func TestSecurityContainerValidation(t *testing.T) {
	// Setup temporary config directory
	tmpDir, err := os.MkdirTemp("", "servworx-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	config.SetConfigDir(tmpDir)

	// Create a dummy config with a malicious container name
	cfg := &config.Config{
		Users: map[string]string{"admin": "hashed_password"},
		Services: []config.ServiceConfig{
			{
				Name:           "MaliciousService",
				ContainerNames: "valid-name; rm -rf /",
			},
		},
	}
	if err := config.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}

	// Mock session
	sessionID := auth.CreateSession("admin")

	t.Run("HandleAPILogsStreamGET rejects malicious container name", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/logs/stream/0", nil)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: sessionID})
		req.SetPathValue("index", "0")

		rr := httptest.NewRecorder()
		HandleAPILogsStreamGET(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status OK, got %d", rr.Code)
		}

		if !strings.Contains(rr.Body.String(), "data: No valid containers found") {
			t.Errorf("expected 'No valid containers found' in response, got %q", rr.Body.String())
		}
	})
}
