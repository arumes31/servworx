package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arumes31/servworx/internal/config"
)

func TestHandleUpdateServicePOSTSecurity(t *testing.T) {
	// Setup a mock config directory
	tmpDir := t.TempDir()
	config.SetConfigDir(tmpDir)

	// Setup mock templates
	templateDir := filepath.Join(tmpDir, "templates")
	os.MkdirAll(templateDir, 0755)
	os.WriteFile(filepath.Join(templateDir, "config.html"), []byte("{{.Error}}"), 0644)
	InitTemplates(templateDir)

	// Create a dummy config and status
	cfg := &config.Config{
		Services: []config.ServiceConfig{
			{Name: "TestService", ContainerNames: "valid-container"},
		},
	}
	_ = config.SaveConfig(cfg)
	_ = config.SaveStatus(&config.Status{Services: []config.ServiceStatus{{Name: "TestService"}}})

	tests := []struct {
		name           string
		containerNames string
		wantError      bool
	}{
		{"Valid container name", "container1,container2", false},
		{"Valid container name with dots", "container.1", false},
		{"Invalid container name semicolon", "container1; rm -rf /", true},
		{"Invalid container name space", "container 1", true},
		{"Invalid container name backtick", "container1`", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := url.Values{}
			form.Add("form_action", "update")
			form.Add("name", "TestService")
			form.Add("website_url", "http://example.com")
			form.Add("container_names", tt.containerNames)
			form.Add("retries", "3")
			form.Add("interval", "60")
			form.Add("grace_period", "300")

			req := httptest.NewRequest("POST", "/update_service/0", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.SetPathValue("index", "0")

			w := httptest.NewRecorder()
			HandleUpdateServicePOST(w, req)

			if tt.wantError {
				if w.Code == http.StatusSeeOther {
					t.Errorf("expected error for container names %q, but got redirect", tt.containerNames)
				}
				if !strings.Contains(w.Body.String(), "Invalid container name") {
					t.Errorf("expected error message for container names %q, but got body: %q", tt.containerNames, w.Body.String())
				}
			} else {
				if w.Code != http.StatusSeeOther {
					t.Errorf("expected success (redirect) for container names %q, but got code %d and body %q", tt.containerNames, w.Code, w.Body.String())
				}
			}
		})
	}
}

func TestHandleViewLogsGETSecurity(t *testing.T) {
	tmpDir := t.TempDir()
	config.SetConfigDir(tmpDir)
	templateDir := filepath.Join(tmpDir, "templates")
	os.MkdirAll(templateDir, 0755)
	os.WriteFile(filepath.Join(templateDir, "config.html"), []byte("{{.Logs}}"), 0644)
	InitTemplates(templateDir)

	cfg := &config.Config{
		Services: []config.ServiceConfig{
			{Name: "TestService", ContainerNames: "valid-container,container;rm -rf /"},
		},
	}
	_ = config.SaveConfig(cfg)
	_ = config.SaveStatus(&config.Status{Services: []config.ServiceStatus{{Name: "TestService"}}})

	req := httptest.NewRequest("GET", "/view_logs/0", nil)
	req.SetPathValue("index", "0")
	w := httptest.NewRecorder()
	HandleViewLogsGET(w, req)

	if !strings.Contains(w.Body.String(), "Invalid container name blocked") {
		t.Errorf("expected error message for invalid container name in logs, but got body: %q", w.Body.String())
	}
}

func TestHandleAPILogsStreamGETSecurity(t *testing.T) {
	tmpDir := t.TempDir()
	config.SetConfigDir(tmpDir)

	cfg := &config.Config{
		Services: []config.ServiceConfig{
			{Name: "TestService", ContainerNames: "container;rm -rf /"},
		},
	}
	_ = config.SaveConfig(cfg)

	req := httptest.NewRequest("GET", "/api/logs/0", nil)
	req.SetPathValue("index", "0")
	w := httptest.NewRecorder()
	HandleAPILogsStreamGET(w, req)

	if !strings.Contains(w.Body.String(), "data: No valid containers found") {
		t.Errorf("expected 'No valid containers found' for invalid container name in SSE stream, but got body: %q", w.Body.String())
	}
}
