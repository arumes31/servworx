package handlers

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/arumes31/servworx/internal/auth"
	"github.com/arumes31/servworx/internal/config"
)

// initTestTemplates sets up minimal HTML templates for handler tests that call ExecuteTemplate
func initTestTemplates(t *testing.T) {
	t.Helper()
	templates = template.Must(template.New("").Funcs(template.FuncMap{
		"div": func(a, b int) int {
			if b == 0 {
				return 0
			}
			return a / b
		},
	}).Parse(`
{{define "login.html"}}LOGIN:{{.}}{{end}}
{{define "config.html"}}CONFIG:{{.}}{{end}}
{{define "change_password.html"}}CHANGEPW:{{.}}{{end}}
`))
}

// makeAuthenticatedRequest creates an HTTP request with a valid session cookie
func makeAuthenticatedRequest(t *testing.T, method, path, body string, username string) *http.Request {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	sessionID := auth.CreateSession(username)
	req.AddCookie(&http.Cookie{
		Name:  "session_id",
		Value: sessionID,
	})
	return req
}

// setupTestConfig creates a temp config dir and seeds config/status
func setupTestConfig(t *testing.T) (cleanup func()) {
	t.Helper()
	tmpDir := t.TempDir()
	originalDir := config.ConfigDir
	config.SetConfigDir(tmpDir)

	// Seed minimal config
	cfg := &config.Config{
		Users: map[string]string{"admin": "$2a$10$X4.EHl7wqmH4Gms0eEUxS.L9pHy.l4J6C6WY3SsLx.FNa7eRwXjHW"}, // "password"
		Services: []config.ServiceConfig{
			{
				Name:                "test-service",
				WebsiteURL:          "http://example.com",
				ContainerNames:      "test-container",
				Retries:             3,
				Interval:            60,
				GracePeriod:         3600,
				AcceptedStatusCodes: []int{200},
				AlertOnFailure:      true,
				AlertOnRecovery:     true,
			},
		},
	}
	_ = config.SaveConfig(cfg)
	_ = config.UpdateStatus(func(s *config.Status) {
		s.Services = []config.ServiceStatus{
			{Name: "test-service", Status: "Up", LastStableStatus: "Up"},
		}
	})

	return func() {
		config.SetConfigDir(originalDir)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// hashPassword
// ──────────────────────────────────────────────────────────────────────────────

func TestHashPassword(t *testing.T) {
	hash, err := hashPassword("mysecretpassword")
	if err != nil {
		t.Fatalf("hashPassword returned error: %v", err)
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Errorf("expected bcrypt hash starting with $2, got: %s", hash)
	}
	if !checkPassword("mysecretpassword", hash) {
		t.Error("expected checkPassword to verify the freshly hashed password")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// migratePasswordToBcrypt
// ──────────────────────────────────────────────────────────────────────────────

func TestMigratePasswordToBcrypt(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()

	// Set a SHA256 hash for admin in config
	sha256Hash := "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f" // password123
	_ = config.UpdateConfig(func(c *config.Config) {
		c.Users["admin"] = sha256Hash
	})

	// Migrate
	migratePasswordToBcrypt("admin", "password123")

	// Verify the stored hash is now bcrypt
	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}
	newHash := cfg.Users["admin"]
	if !strings.HasPrefix(newHash, "$2") {
		t.Errorf("expected bcrypt hash after migration, got: %s", newHash)
	}
	if !checkPassword("password123", newHash) {
		t.Error("migrated bcrypt hash does not verify password")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// parseStatusCodes
// ──────────────────────────────────────────────────────────────────────────────

func TestParseStatusCodes(t *testing.T) {
	tests := []struct {
		input    string
		expected []int
		wantErr  bool
	}{
		{"", []int{200}, false},
		{"   ", []int{200}, false},
		{"200", []int{200}, false},
		{"200,201,302", []int{200, 201, 302}, false},
		{"200, 301 , 404", []int{200, 301, 404}, false},
		{"abc", nil, true},
		{"200,xyz", nil, true},
	}

	for _, tt := range tests {
		codes, err := parseStatusCodes(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseStatusCodes(%q) expected error, got nil", tt.input)
			}
		} else {
			if err != nil {
				t.Errorf("parseStatusCodes(%q) unexpected error: %v", tt.input, err)
				continue
			}
			if len(codes) != len(tt.expected) {
				t.Errorf("parseStatusCodes(%q) = %v, want %v", tt.input, codes, tt.expected)
				continue
			}
			for i, c := range codes {
				if c != tt.expected[i] {
					t.Errorf("parseStatusCodes(%q)[%d] = %d, want %d", tt.input, i, c, tt.expected[i])
				}
			}
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// getNotificationProviders
// ──────────────────────────────────────────────────────────────────────────────

func TestGetNotificationProviders_AllMissing(t *testing.T) {
	// Clear all notification env vars
	vars := []string{
		"NOTIFICATION_WEBHOOK_URL", "NOTIFICATION_MSTEAMS_URL",
		"NOTIFICATION_TELEGRAM_TOKEN", "NOTIFICATION_TELEGRAM_CHAT_ID",
		"NOTIFICATION_SMTP_HOST", "NOTIFICATION_SMTP_PORT",
		"NOTIFICATION_SMTP_FROM", "NOTIFICATION_SMTP_TO",
		"NOTIFICATION_DISCORD_URL", "NOTIFICATION_GOTIFY_URL",
		"NOTIFICATION_GOTIFY_TOKEN", "NOTIFICATION_PUSHOVER_TOKEN",
		"NOTIFICATION_PUSHOVER_USER",
	}
	for _, v := range vars {
		os.Unsetenv(v)
	}

	providers := getNotificationProviders()
	for k, v := range providers {
		if v {
			t.Errorf("expected provider %s to be false when env vars are missing", k)
		}
	}
}

func TestGetNotificationProviders_AllPresent(t *testing.T) {
	os.Setenv("NOTIFICATION_WEBHOOK_URL", "http://hook")
	os.Setenv("NOTIFICATION_MSTEAMS_URL", "http://teams")
	os.Setenv("NOTIFICATION_TELEGRAM_TOKEN", "tok")
	os.Setenv("NOTIFICATION_TELEGRAM_CHAT_ID", "chatid")
	os.Setenv("NOTIFICATION_SMTP_HOST", "localhost")
	os.Setenv("NOTIFICATION_SMTP_PORT", "587")
	os.Setenv("NOTIFICATION_SMTP_FROM", "a@b.com")
	os.Setenv("NOTIFICATION_SMTP_TO", "c@d.com")
	os.Setenv("NOTIFICATION_DISCORD_URL", "http://discord")
	os.Setenv("NOTIFICATION_GOTIFY_URL", "http://gotify")
	os.Setenv("NOTIFICATION_GOTIFY_TOKEN", "gtok")
	os.Setenv("NOTIFICATION_PUSHOVER_TOKEN", "ptok")
	os.Setenv("NOTIFICATION_PUSHOVER_USER", "puser")
	defer func() {
		os.Unsetenv("NOTIFICATION_WEBHOOK_URL")
		os.Unsetenv("NOTIFICATION_MSTEAMS_URL")
		os.Unsetenv("NOTIFICATION_TELEGRAM_TOKEN")
		os.Unsetenv("NOTIFICATION_TELEGRAM_CHAT_ID")
		os.Unsetenv("NOTIFICATION_SMTP_HOST")
		os.Unsetenv("NOTIFICATION_SMTP_PORT")
		os.Unsetenv("NOTIFICATION_SMTP_FROM")
		os.Unsetenv("NOTIFICATION_SMTP_TO")
		os.Unsetenv("NOTIFICATION_DISCORD_URL")
		os.Unsetenv("NOTIFICATION_GOTIFY_URL")
		os.Unsetenv("NOTIFICATION_GOTIFY_TOKEN")
		os.Unsetenv("NOTIFICATION_PUSHOVER_TOKEN")
		os.Unsetenv("NOTIFICATION_PUSHOVER_USER")
	}()

	providers := getNotificationProviders()
	for k, v := range providers {
		if !v {
			t.Errorf("expected provider %s to be true when env vars are set", k)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// HandleLoginGET
// ──────────────────────────────────────────────────────────────────────────────

func TestHandleLoginGET_NoSession(t *testing.T) {
	initTestTemplates(t)
	req := httptest.NewRequest("GET", "/login", nil)
	rr := httptest.NewRecorder()
	HandleLoginGET(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "LOGIN:") {
		t.Errorf("expected login template response, got: %s", rr.Body.String())
	}
}

func TestHandleLoginGET_WithSession(t *testing.T) {
	initTestTemplates(t)
	req := makeAuthenticatedRequest(t, "GET", "/login", "", "testuser")
	rr := httptest.NewRecorder()
	HandleLoginGET(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", rr.Code)
	}
	if rr.Header().Get("Location") != "/config" {
		t.Errorf("expected redirect to /config, got %s", rr.Header().Get("Location"))
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// HandleLoginPOST
// ──────────────────────────────────────────────────────────────────────────────

func TestHandleLoginPOST_InsecureConnection(t *testing.T) {
	initTestTemplates(t)
	// Non-HTTPS request (r.TLS == nil, no X-Forwarded-Proto header)
	body := url.Values{"username": {"admin"}, "password": {"pass"}}.Encode()
	req := httptest.NewRequest("POST", "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	HandleLoginPOST(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with error message, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "LOGIN:") {
		t.Errorf("expected login template in response, got: %s", rr.Body.String())
	}
}

func TestHandleLoginPOST_InvalidCredentials(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	body := url.Values{"username": {"admin"}, "password": {"wrongpassword"}}.Encode()
	req := httptest.NewRequest("POST", "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-Proto", "https")
	rr := httptest.NewRecorder()
	HandleLoginPOST(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with error, got %d", rr.Code)
	}
}

func TestHandleLoginPOST_UnknownUser(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	body := url.Values{"username": {"unknownuser"}, "password": {"pass"}}.Encode()
	req := httptest.NewRequest("POST", "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-Proto", "https")
	rr := httptest.NewRecorder()
	HandleLoginPOST(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestHandleLoginPOST_SuccessfulLogin(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	// Set a known bcrypt hash for admin (password: "testpass123")
	hash, _ := hashPassword("testpass123")
	_ = config.UpdateConfig(func(c *config.Config) {
		c.Users["admin"] = hash
	})

	body := url.Values{"username": {"admin"}, "password": {"testpass123"}}.Encode()
	req := httptest.NewRequest("POST", "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-Proto", "https")
	rr := httptest.NewRecorder()
	HandleLoginPOST(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", rr.Code)
	}
	if rr.Header().Get("Location") != "/config" {
		t.Errorf("expected redirect to /config, got %s", rr.Header().Get("Location"))
	}
}

func TestHandleLoginPOST_SHA256Migration(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	// Set SHA256 hash for admin (password: "password123")
	sha256Hash := "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f"
	_ = config.UpdateConfig(func(c *config.Config) {
		c.Users["admin"] = sha256Hash
	})

	body := url.Values{"username": {"admin"}, "password": {"password123"}}.Encode()
	req := httptest.NewRequest("POST", "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-Proto", "https")
	rr := httptest.NewRecorder()
	HandleLoginPOST(rr, req)

	// Should migrate and redirect to /change_password (default password is "changeme" which doesn't match)
	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected redirect after SHA256 login, got %d", rr.Code)
	}

	// Verify hash was migrated to bcrypt
	cfg, _ := config.LoadConfig()
	if !strings.HasPrefix(cfg.Users["admin"], "$2") {
		t.Error("expected password hash to be migrated to bcrypt after login")
	}
}

func TestHandleLoginPOST_AdminDefaultPasswordRedirect(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	// Set bcrypt hash for "changeme"
	hash, _ := hashPassword("changeme")
	_ = config.UpdateConfig(func(c *config.Config) {
		c.Users["admin"] = hash
	})

	body := url.Values{"username": {"admin"}, "password": {"changeme"}}.Encode()
	req := httptest.NewRequest("POST", "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-Proto", "https")
	rr := httptest.NewRecorder()
	HandleLoginPOST(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected redirect, got %d", rr.Code)
	}
	if rr.Header().Get("Location") != "/change_password" {
		t.Errorf("expected redirect to /change_password for default password, got %s", rr.Header().Get("Location"))
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// HandleLogout
// ──────────────────────────────────────────────────────────────────────────────

func TestHandleLogout(t *testing.T) {
	initTestTemplates(t)
	req := makeAuthenticatedRequest(t, "GET", "/logout", "", "testuser")
	rr := httptest.NewRecorder()
	HandleLogout(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", rr.Code)
	}
	if rr.Header().Get("Location") != "/login" {
		t.Errorf("expected redirect to /login, got %s", rr.Header().Get("Location"))
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// HandleChangePasswordGET
// ──────────────────────────────────────────────────────────────────────────────

func TestHandleChangePasswordGET(t *testing.T) {
	initTestTemplates(t)
	req := makeAuthenticatedRequest(t, "GET", "/change_password", "", "admin")
	rr := httptest.NewRecorder()
	HandleChangePasswordGET(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "CHANGEPW:") {
		t.Errorf("expected change_password template, got: %s", rr.Body.String())
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// HandleChangePasswordPOST
// ──────────────────────────────────────────────────────────────────────────────

func TestHandleChangePasswordPOST_PasswordMismatch(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	body := url.Values{
		"new_password":     {"newpass123"},
		"confirm_password": {"different456"},
	}.Encode()
	req := makeAuthenticatedRequest(t, "POST", "/change_password", body, "admin")
	rr := httptest.NewRecorder()
	HandleChangePasswordPOST(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with error, got %d", rr.Code)
	}
}

func TestHandleChangePasswordPOST_WeakPassword(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	body := url.Values{
		"new_password":     {"short"},
		"confirm_password": {"short"},
	}.Encode()
	req := makeAuthenticatedRequest(t, "POST", "/change_password", body, "admin")
	rr := httptest.NewRecorder()
	HandleChangePasswordPOST(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with error, got %d", rr.Code)
	}
}

func TestHandleChangePasswordPOST_Success(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	body := url.Values{
		"new_password":     {"strongpassword123"},
		"confirm_password": {"strongpassword123"},
	}.Encode()
	req := makeAuthenticatedRequest(t, "POST", "/change_password", body, "admin")
	rr := httptest.NewRecorder()
	HandleChangePasswordPOST(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", rr.Code)
	}
	if rr.Header().Get("Location") != "/config" {
		t.Errorf("expected redirect to /config, got %s", rr.Header().Get("Location"))
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// requireAuth middleware
// ──────────────────────────────────────────────────────────────────────────────

func TestRequireAuth_NoSession(t *testing.T) {
	initTestTemplates(t)
	handler := requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/config", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", rr.Code)
	}
	if rr.Header().Get("Location") != "/login" {
		t.Errorf("expected redirect to /login, got %s", rr.Header().Get("Location"))
	}
}

func TestRequireAuth_AdminDefaultPassword(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	// Set "changeme" as admin's password
	hash, _ := hashPassword("changeme")
	_ = config.UpdateConfig(func(c *config.Config) {
		c.Users["admin"] = hash
	})

	called := false
	handler := requireAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := makeAuthenticatedRequest(t, "GET", "/config", "", "admin")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if called {
		t.Error("expected handler NOT to be called with default changeme password")
	}
	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected redirect to change_password, got %d", rr.Code)
	}
}

func TestRequireAuth_ValidSession(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	called := false
	handler := requireAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := makeAuthenticatedRequest(t, "GET", "/config", "", "regularuser")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if !called {
		t.Error("expected handler to be called with valid session")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// HandleConfigGET
// ──────────────────────────────────────────────────────────────────────────────

func TestHandleConfigGET(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	req := makeAuthenticatedRequest(t, "GET", "/config", "", "admin")
	rr := httptest.NewRecorder()
	HandleConfigGET(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// HandleAPIStatusGET
// ──────────────────────────────────────────────────────────────────────────────

func TestHandleAPIStatusGET(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	req := makeAuthenticatedRequest(t, "GET", "/api/status", "", "admin")
	rr := httptest.NewRecorder()
	HandleAPIStatusGET(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if rr.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", rr.Header().Get("Content-Type"))
	}

	var response APIViewData
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse JSON response: %v", err)
	}
}

// TestHandleAPIStatusGET_WithDownSince covers the DownSince enrichment path
func TestHandleAPIStatusGET_WithDownSince(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	// Set DownSince on the service status
	downStr := time.Now().Add(-1 * time.Hour).Format("2006-01-02 15:04:05")
	_ = config.UpdateStatus(func(s *config.Status) {
		s.Services[0].DownSince = &downStr
		s.Services[0].Status = "Down"
		s.Services[0].LastStableStatus = "Down"
	})

	req := makeAuthenticatedRequest(t, "GET", "/api/status", "", "admin")
	rr := httptest.NewRecorder()
	HandleAPIStatusGET(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// HandleUpdateServicePOST
// ──────────────────────────────────────────────────────────────────────────────

func TestHandleUpdateServicePOST_InvalidIndex(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	req := makeAuthenticatedRequest(t, "POST", "/update_service/abc", "", "admin")
	req.SetPathValue("index", "abc")
	rr := httptest.NewRecorder()
	HandleUpdateServicePOST(rr, req)
	// Should show config error page (not panic)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with error page, got %d", rr.Code)
	}
}

func TestHandleUpdateServicePOST_OutOfBoundsIndex(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	body := url.Values{"form_action": {"update"}}.Encode()
	req := makeAuthenticatedRequest(t, "POST", "/update_service/999", body, "admin")
	req.SetPathValue("index", "999")
	rr := httptest.NewRecorder()
	HandleUpdateServicePOST(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with error, got %d", rr.Code)
	}
}

func TestHandleUpdateServicePOST_DeleteAction(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	body := url.Values{"form_action": {"delete"}}.Encode()
	req := makeAuthenticatedRequest(t, "POST", "/update_service/0", body, "admin")
	req.SetPathValue("index", "0")
	rr := httptest.NewRecorder()
	HandleUpdateServicePOST(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected redirect after delete, got %d", rr.Code)
	}
}

func TestHandleUpdateServicePOST_UpdateAction(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	body := url.Values{
		"form_action":           {"update"},
		"name":                  {"updated-service"},
		"website_url":           {"http://newurl.com"},
		"container_names":       {"nginx"},
		"retries":               {"5"},
		"interval":              {"30"},
		"grace_period":          {"1800"},
		"accepted_status_codes": {"200"},
		"alert_on_failure":      {"on"},
		"alert_on_recovery":     {"on"},
		"alert_on_restart":      {"on"},
		"alert_repeat_interval": {"0"},
		"alert_max_repeats":     {"0"},
	}.Encode()
	req := makeAuthenticatedRequest(t, "POST", "/update_service/0", body, "admin")
	req.SetPathValue("index", "0")
	rr := httptest.NewRecorder()
	HandleUpdateServicePOST(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected redirect after update, got %d", rr.Code)
	}
}

func TestHandleUpdateServicePOST_InvalidRetries(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	body := url.Values{
		"form_action":  {"update"},
		"name":         {"svc"},
		"retries":      {"notanumber"},
		"interval":     {"60"},
		"grace_period": {"3600"},
	}.Encode()
	req := makeAuthenticatedRequest(t, "POST", "/update_service/0", body, "admin")
	req.SetPathValue("index", "0")
	rr := httptest.NewRecorder()
	HandleUpdateServicePOST(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with error page, got %d", rr.Code)
	}
}

func TestHandleUpdateServicePOST_InvalidContainerName(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	body := url.Values{
		"form_action":           {"update"},
		"name":                  {"svc"},
		"website_url":           {"http://example.com"},
		"container_names":       {"bad name; rm -rf /"},
		"retries":               {"3"},
		"interval":              {"60"},
		"grace_period":          {"3600"},
		"accepted_status_codes": {"200"},
	}.Encode()
	req := makeAuthenticatedRequest(t, "POST", "/update_service/0", body, "admin")
	req.SetPathValue("index", "0")
	rr := httptest.NewRecorder()
	HandleUpdateServicePOST(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with error page for invalid container name, got %d", rr.Code)
	}
}

func TestHandleUpdateServicePOST_InvalidStatusCodes(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	body := url.Values{
		"form_action":           {"update"},
		"name":                  {"svc"},
		"website_url":           {"http://example.com"},
		"container_names":       {"nginx"},
		"retries":               {"3"},
		"interval":              {"60"},
		"grace_period":          {"3600"},
		"accepted_status_codes": {"notacode"},
	}.Encode()
	req := makeAuthenticatedRequest(t, "POST", "/update_service/0", body, "admin")
	req.SetPathValue("index", "0")
	rr := httptest.NewRecorder()
	HandleUpdateServicePOST(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with error page for invalid status codes, got %d", rr.Code)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// HandleAddServicePOST
// ──────────────────────────────────────────────────────────────────────────────

func TestHandleAddServicePOST(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	req := makeAuthenticatedRequest(t, "POST", "/add_service", "", "admin")
	rr := httptest.NewRecorder()
	HandleAddServicePOST(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected redirect, got %d", rr.Code)
	}

	// Verify service was added
	cfg, _ := config.LoadConfig()
	if len(cfg.Services) < 2 {
		t.Errorf("expected at least 2 services after add, got %d", len(cfg.Services))
	}
}

func TestHandleAddServicePOST_AJAX(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	req := makeAuthenticatedRequest(t, "POST", "/add_service", "", "admin")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	rr := httptest.NewRecorder()
	HandleAddServicePOST(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for AJAX request, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "success") {
		t.Errorf("expected JSON success response, got: %s", rr.Body.String())
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// HandleForceRestartPOST
// ──────────────────────────────────────────────────────────────────────────────

func TestHandleForceRestartPOST_InvalidIndex(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	req := makeAuthenticatedRequest(t, "POST", "/force_restart/abc", "", "admin")
	req.SetPathValue("index", "abc")
	rr := httptest.NewRecorder()
	HandleForceRestartPOST(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with error page, got %d", rr.Code)
	}
}

func TestHandleForceRestartPOST_OutOfBoundsIndex(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	req := makeAuthenticatedRequest(t, "POST", "/force_restart/999", "", "admin")
	req.SetPathValue("index", "999")
	rr := httptest.NewRecorder()
	HandleForceRestartPOST(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with error, got %d", rr.Code)
	}
}

func TestHandleForceRestartPOST_Valid(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	req := makeAuthenticatedRequest(t, "POST", "/force_restart/0", "", "admin")
	req.SetPathValue("index", "0")
	rr := httptest.NewRecorder()
	HandleForceRestartPOST(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected redirect, got %d", rr.Code)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// HandlePauseMonitoringPOST
// ──────────────────────────────────────────────────────────────────────────────

func TestHandlePauseMonitoringPOST_InvalidIndex(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	req := makeAuthenticatedRequest(t, "POST", "/pause_monitoring/abc", "", "admin")
	req.SetPathValue("index", "abc")
	rr := httptest.NewRecorder()
	HandlePauseMonitoringPOST(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with error, got %d", rr.Code)
	}
}

func TestHandlePauseMonitoringPOST_OutOfBoundsIndex(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	req := makeAuthenticatedRequest(t, "POST", "/pause_monitoring/999", "", "admin")
	req.SetPathValue("index", "999")
	rr := httptest.NewRecorder()
	HandlePauseMonitoringPOST(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with error, got %d", rr.Code)
	}
}

func TestHandlePauseMonitoringPOST_Toggle(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	req := makeAuthenticatedRequest(t, "POST", "/pause_monitoring/0", "", "admin")
	req.SetPathValue("index", "0")
	rr := httptest.NewRecorder()
	HandlePauseMonitoringPOST(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected redirect after pause toggle, got %d", rr.Code)
	}

	cfg, _ := config.LoadConfig()
	if !cfg.Services[0].Paused {
		t.Error("expected service to be paused after toggle")
	}

	// Toggle back
	req2 := makeAuthenticatedRequest(t, "POST", "/pause_monitoring/0", "", "admin")
	req2.SetPathValue("index", "0")
	rr2 := httptest.NewRecorder()
	HandlePauseMonitoringPOST(rr2, req2)

	cfg, _ = config.LoadConfig()
	if cfg.Services[0].Paused {
		t.Error("expected service to be unpaused after second toggle")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// HandleViewLogsGET
// ──────────────────────────────────────────────────────────────────────────────

func TestHandleViewLogsGET_InvalidIndex(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	req := makeAuthenticatedRequest(t, "GET", "/view_logs/abc", "", "admin")
	req.SetPathValue("index", "abc")
	rr := httptest.NewRecorder()
	HandleViewLogsGET(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with error, got %d", rr.Code)
	}
}

func TestHandleViewLogsGET_OutOfBoundsIndex(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	req := makeAuthenticatedRequest(t, "GET", "/view_logs/999", "", "admin")
	req.SetPathValue("index", "999")
	rr := httptest.NewRecorder()
	HandleViewLogsGET(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with error, got %d", rr.Code)
	}
}

func TestHandleViewLogsGET_Valid(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	req := makeAuthenticatedRequest(t, "GET", "/view_logs/0", "", "admin")
	req.SetPathValue("index", "0")
	rr := httptest.NewRecorder()
	HandleViewLogsGET(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestHandleViewLogsGET_InvalidContainerName(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	// Set invalid container name
	_ = config.UpdateConfig(func(c *config.Config) {
		c.Services[0].ContainerNames = "bad name; rm -rf /"
	})

	req := makeAuthenticatedRequest(t, "GET", "/view_logs/0", "", "admin")
	req.SetPathValue("index", "0")
	rr := httptest.NewRecorder()
	HandleViewLogsGET(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 even with invalid container name, got %d", rr.Code)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// HandleAPINotificationTestPOST
// ──────────────────────────────────────────────────────────────────────────────

func TestHandleAPINotificationTestPOST_InvalidIndex(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	body := url.Values{"index": {"notanumber"}, "provider": {"webhook"}}.Encode()
	req := makeAuthenticatedRequest(t, "POST", "/api/notifications/test", body, "admin")
	rr := httptest.NewRecorder()
	HandleAPINotificationTestPOST(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleAPINotificationTestPOST_MissingProvider(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	body := url.Values{"index": {"0"}}.Encode()
	req := makeAuthenticatedRequest(t, "POST", "/api/notifications/test", body, "admin")
	rr := httptest.NewRecorder()
	HandleAPINotificationTestPOST(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing provider, got %d", rr.Code)
	}
}

func TestHandleAPINotificationTestPOST_OutOfBoundsIndex(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	body := url.Values{"index": {"999"}, "provider": {"webhook"}}.Encode()
	req := makeAuthenticatedRequest(t, "POST", "/api/notifications/test", body, "admin")
	rr := httptest.NewRecorder()
	HandleAPINotificationTestPOST(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for out-of-bounds index, got %d", rr.Code)
	}
}

func TestHandleAPINotificationTestPOST_ProviderFails(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	// Unset webhook URL so it fails
	os.Unsetenv("NOTIFICATION_WEBHOOK_URL")

	body := url.Values{"index": {"0"}, "provider": {"webhook"}}.Encode()
	req := makeAuthenticatedRequest(t, "POST", "/api/notifications/test", body, "admin")
	rr := httptest.NewRecorder()
	HandleAPINotificationTestPOST(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for provider failure, got %d", rr.Code)
	}
}

func TestHandleAPINotificationTestPOST_Success(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	// Start a mock webhook server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	os.Setenv("NOTIFICATION_WEBHOOK_URL", ts.URL)
	defer os.Unsetenv("NOTIFICATION_WEBHOOK_URL")

	body := url.Values{"index": {"0"}, "provider": {"webhook"}}.Encode()
	req := makeAuthenticatedRequest(t, "POST", "/api/notifications/test", body, "admin")
	rr := httptest.NewRecorder()
	HandleAPINotificationTestPOST(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for successful test, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "success") {
		t.Errorf("expected success in response, got: %s", rr.Body.String())
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// HandleAPISnoozePOST
// ──────────────────────────────────────────────────────────────────────────────

func TestHandleAPISnoozePOST_InvalidDuration(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	body := url.Values{"duration": {"notanumber"}}.Encode()
	req := makeAuthenticatedRequest(t, "POST", "/api/snooze/0", body, "admin")
	req.SetPathValue("index", "0")
	rr := httptest.NewRecorder()
	HandleAPISnoozePOST(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid duration, got %d", rr.Code)
	}
}

func TestHandleAPISnoozePOST_SnoozeEnable(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	body := url.Values{"duration": {"30"}}.Encode() // snooze for 30 mins
	req := makeAuthenticatedRequest(t, "POST", "/api/snooze/0", body, "admin")
	req.SetPathValue("index", "0")
	rr := httptest.NewRecorder()
	HandleAPISnoozePOST(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "snoozed") {
		t.Errorf("expected 'snoozed' in response, got: %s", rr.Body.String())
	}

	// Verify snooze was persisted
	cfg, _ := config.LoadConfig()
	if cfg.Services[0].AlertSnoozeUntil <= time.Now().Unix() {
		t.Error("expected AlertSnoozeUntil to be in the future")
	}
}

func TestHandleAPISnoozePOST_SnoozeDisable(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	body := url.Values{"duration": {"0"}}.Encode() // clear snooze
	req := makeAuthenticatedRequest(t, "POST", "/api/snooze/0", body, "admin")
	req.SetPathValue("index", "0")
	rr := httptest.NewRecorder()
	HandleAPISnoozePOST(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "unsnoozed") {
		t.Errorf("expected 'unsnoozed' in response, got: %s", rr.Body.String())
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// RegisterRoutes + static handlers
// ──────────────────────────────────────────────────────────────────────────────

func TestRegisterRoutes_FaviconRoute(t *testing.T) {
	initTestTemplates(t)
	mux := http.NewServeMux()
	RegisterRoutes(mux)

	req := httptest.NewRequest("GET", "/favicon.ico", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for favicon.ico, got %d", rr.Code)
	}
	if rr.Header().Get("Content-Type") != "image/svg+xml" {
		t.Errorf("expected SVG content type, got %s", rr.Header().Get("Content-Type"))
	}
}

func TestRegisterRoutes_RootNoSession(t *testing.T) {
	initTestTemplates(t)
	mux := http.NewServeMux()
	RegisterRoutes(mux)

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected redirect for unauthenticated root, got %d", rr.Code)
	}
	if rr.Header().Get("Location") != "/login" {
		t.Errorf("expected redirect to /login, got %s", rr.Header().Get("Location"))
	}
}

func TestRegisterRoutes_RootWithSession(t *testing.T) {
	initTestTemplates(t)
	mux := http.NewServeMux()
	RegisterRoutes(mux)

	sessionID := auth.CreateSession("testuser")
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: sessionID})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected redirect to /config for authenticated root, got %d", rr.Code)
	}
	if rr.Header().Get("Location") != "/config" {
		t.Errorf("expected redirect to /config, got %s", rr.Header().Get("Location"))
	}
}

func TestRegisterRoutes_NotFound(t *testing.T) {
	initTestTemplates(t)
	mux := http.NewServeMux()
	RegisterRoutes(mux)

	sessionID := auth.CreateSession("testuser")
	req := httptest.NewRequest("GET", "/nonexistent-page", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: sessionID})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown route, got %d", rr.Code)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// ConfigGET with DownSince and UpSince enrichment
// ──────────────────────────────────────────────────────────────────────────────

func TestHandleConfigGET_WithDownAndUpSince(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	downStr := time.Now().Add(-2 * time.Hour).Format("2006-01-02 15:04:05")
	upStr := time.Now().Add(-1 * time.Hour).Format("2006-01-02 15:04:05")
	_ = config.UpdateStatus(func(s *config.Status) {
		s.Services[0].DownSince = &downStr
		s.Services[0].UpSince = &upStr
	})

	req := makeAuthenticatedRequest(t, "GET", "/config", "", "admin")
	rr := httptest.NewRecorder()
	HandleConfigGET(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestHandleConfigGET_WithInvalidTimestamp(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	invalidTimestamp := "not-a-valid-time"
	_ = config.UpdateStatus(func(s *config.Status) {
		s.Services[0].DownSince = &invalidTimestamp
		s.Services[0].UpSince = &invalidTimestamp
	})

	req := makeAuthenticatedRequest(t, "GET", "/config", "", "admin")
	rr := httptest.NewRecorder()
	HandleConfigGET(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 even with invalid timestamp, got %d", rr.Code)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// HandleUpdateServicePOST — rename service (oldName != newName path)
// ──────────────────────────────────────────────────────────────────────────────

func TestHandleUpdateServicePOST_RenameService(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	body := url.Values{
		"form_action":           {"update"},
		"name":                  {"renamed-service"},
		"website_url":           {"http://example.com"},
		"container_names":       {"nginx"},
		"retries":               {"3"},
		"interval":              {"60"},
		"grace_period":          {"3600"},
		"accepted_status_codes": {"200"},
		"alert_repeat_interval": {"0"},
		"alert_max_repeats":     {"0"},
	}.Encode()
	req := makeAuthenticatedRequest(t, "POST", "/update_service/0", body, "admin")
	req.SetPathValue("index", "0")
	rr := httptest.NewRecorder()
	HandleUpdateServicePOST(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected redirect after rename, got %d", rr.Code)
	}

	// Verify name was updated in config
	cfg, _ := config.LoadConfig()
	if len(cfg.Services) == 0 {
		t.Fatal("expected at least one service after rename")
	}
	if cfg.Services[0].Name != "renamed-service" {
		t.Errorf("expected service name 'renamed-service', got %s", cfg.Services[0].Name)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// HandleAPISnoozePOST — invalid index
// ──────────────────────────────────────────────────────────────────────────────

func TestHandleAPISnoozePOST_InvalidIndex(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	body := url.Values{"duration": {"30"}}.Encode()
	req := makeAuthenticatedRequest(t, "POST", "/api/snooze/abc", body, "admin")
	req.SetPathValue("index", "abc")
	rr := httptest.NewRecorder()
	HandleAPISnoozePOST(rr, req)
	// parseIndex calls renderConfigWithError (200), so WriteHeader(400) is a no-op after that
	// The response body will contain the JSON error message
	if !strings.Contains(rr.Body.String(), "Invalid") {
		t.Errorf("expected error message for invalid index, got: %s", rr.Body.String())
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// HandleAPIStatusGET — with UpSince enrichment
// ──────────────────────────────────────────────────────────────────────────────

func TestHandleAPIStatusGET_WithUpSince(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	upStr := time.Now().Add(-30 * time.Minute).Format("2006-01-02 15:04:05")
	_ = config.UpdateStatus(func(s *config.Status) {
		s.Services[0].UpSince = &upStr
	})

	req := makeAuthenticatedRequest(t, "GET", "/api/status", "", "admin")
	rr := httptest.NewRecorder()
	HandleAPIStatusGET(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// HandleAPIStatusGET — invalid timestamps
// ──────────────────────────────────────────────────────────────────────────────

func TestHandleAPIStatusGET_InvalidTimestamps(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	bad := "not-a-time"
	_ = config.UpdateStatus(func(s *config.Status) {
		s.Services[0].DownSince = &bad
		s.Services[0].UpSince = &bad
	})

	req := makeAuthenticatedRequest(t, "GET", "/api/status", "", "admin")
	rr := httptest.NewRecorder()
	HandleAPIStatusGET(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 even with bad timestamps, got %d", rr.Code)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers to format
// ──────────────────────────────────────────────────────────────────────────────

func TestParseIndex_Valid(t *testing.T) {
	initTestTemplates(t)
	req := httptest.NewRequest("GET", "/something/5", nil)
	req.SetPathValue("index", "5")
	rr := httptest.NewRecorder()

	idx, ok := parseIndex(rr, req)
	if !ok {
		t.Error("expected parseIndex to succeed")
	}
	if idx != 5 {
		t.Errorf("expected index 5, got %d", idx)
	}
}

func TestParseIndex_Invalid(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	req := httptest.NewRequest("GET", "/something/notanumber", nil)
	req.SetPathValue("index", "notanumber")
	rr := httptest.NewRecorder()

	_, ok := parseIndex(rr, req)
	if ok {
		t.Error("expected parseIndex to fail")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// InitTemplates
// ──────────────────────────────────────────────────────────────────────────────

func TestInitTemplates(t *testing.T) {
	// Use actual templates dir for a smoke test of InitTemplates
	templatesDir := "../../templates"
	if _, err := os.Stat(templatesDir); os.IsNotExist(err) {
		t.Skip("templates directory not found, skipping InitTemplates test")
	}

	// Should not panic
	InitTemplates(templatesDir)

	if templates == nil {
		t.Error("expected templates to be initialized")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// HandleUpdateServicePOST — negative alert values
// ──────────────────────────────────────────────────────────────────────────────

func TestHandleUpdateServicePOST_NegativeAlertValues(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	body := url.Values{
		"form_action":           {"update"},
		"name":                  {"svc"},
		"website_url":           {"http://example.com"},
		"container_names":       {"nginx"},
		"retries":               {"3"},
		"interval":              {"60"},
		"grace_period":          {"3600"},
		"accepted_status_codes": {"200"},
		"alert_repeat_interval": {"-5"}, // negative -> should be set to 0
		"alert_max_repeats":     {"-2"}, // negative -> should be set to 0
	}.Encode()
	req := makeAuthenticatedRequest(t, "POST", "/update_service/0", body, "admin")
	req.SetPathValue("index", "0")
	rr := httptest.NewRecorder()
	HandleUpdateServicePOST(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected redirect, got %d: %s", rr.Code, rr.Body.String())
	}

	cfg, _ := config.LoadConfig()
	if cfg.Services[0].AlertRepeatInterval < 0 {
		t.Error("expected AlertRepeatInterval >= 0")
	}
	if cfg.Services[0].AlertMaxRepeats < 0 {
		t.Error("expected AlertMaxRepeats >= 0")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// HandleUpdateServicePOST — notification providers disabled without env vars
// ──────────────────────────────────────────────────────────────────────────────

func TestHandleUpdateServicePOST_NotificationGuard(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	// Clear all notification env vars
	for _, v := range []string{"NOTIFICATION_WEBHOOK_URL", "NOTIFICATION_DISCORD_URL"} {
		os.Unsetenv(v)
	}

	body := url.Values{
		"form_action":           {"update"},
		"name":                  {"svc"},
		"website_url":           {"http://example.com"},
		"container_names":       {"nginx"},
		"retries":               {"3"},
		"interval":              {"60"},
		"grace_period":          {"3600"},
		"accepted_status_codes": {"200"},
		"enable_webhook":        {"on"}, // Should be ignored due to missing env var
		"enable_discord":        {"on"}, // Should be ignored
		"alert_repeat_interval": {"0"},
		"alert_max_repeats":     {"0"},
	}.Encode()
	req := makeAuthenticatedRequest(t, "POST", "/update_service/0", body, "admin")
	req.SetPathValue("index", "0")
	rr := httptest.NewRecorder()
	HandleUpdateServicePOST(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected redirect, got %d", rr.Code)
	}

	// Verify webhook and discord are NOT enabled despite being requested
	cfg, _ := config.LoadConfig()
	if cfg.Services[0].EnableWebhook {
		t.Error("expected EnableWebhook to be false when NOTIFICATION_WEBHOOK_URL is not set")
	}
	if cfg.Services[0].EnableDiscord {
		t.Error("expected EnableDiscord to be false when NOTIFICATION_DISCORD_URL is not set")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// HandleAPIStatusGET — services mismatch (more status entries than config)
// ──────────────────────────────────────────────────────────────────────────────

func TestHandleAPIStatusGET_StatusServicesMismatch(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	// Add extra status entry without config counterpart
	_ = config.UpdateStatus(func(s *config.Status) {
		s.Services = append(s.Services, config.ServiceStatus{
			Name:   "orphan-service",
			Status: "Unknown",
		})
	})

	req := makeAuthenticatedRequest(t, "GET", "/api/status", "", "admin")
	rr := httptest.NewRecorder()
	HandleAPIStatusGET(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestFormatDurationNegative(t *testing.T) {
	result := formatDuration(-100)
	if result != "0 seconds" {
		t.Errorf("expected '0 seconds' for negative input, got %s", result)
	}
}

func TestFormatDurationZero(t *testing.T) {
	result := formatDuration(0)
	if result != "0 seconds" {
		t.Errorf("expected '0 seconds' for zero input, got %s", result)
	}
}

// Ensure a large fmt.Sprintf placeholder is not used in test
var _ = fmt.Sprintf
