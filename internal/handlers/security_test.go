package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arumes31/servworx/internal/auth"
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
			name:             "Hyphen prefixed name blocked, fallback to valid",
			index:            "2",
			expectAllBlocked: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config.ClearCache()
			req := httptest.NewRequest("GET", "/api/logs/stream/"+tt.index, nil)
			// Mocking path value since it's used in parseIndex (mux.HandleFunc("GET /api/logs/stream/{index}"...))
			req.SetPathValue("index", tt.index)
			req.AddCookie(&http.Cookie{Name: "session_id", Value: auth.CreateSession("admin")})

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

// withTrustedProxies overrides the TRUSTED_PROXIES setting for one test.
func withTrustedProxies(t *testing.T, raw string) {
	t.Helper()
	prev := trustedProxies
	prefixes := parseTrustedProxies(raw)
	trustedProxies = func() []netip.Prefix { return prefixes }
	t.Cleanup(func() { trustedProxies = prev })
}

func TestIsSecureRequest_TrustedProxyOnly(t *testing.T) {
	tests := []struct {
		proxies string
		remote  string
		want    bool
	}{
		{"loopback", "127.0.0.1:1234", true},
		{"loopback", "[::1]:1234", true},
		// Private peers are not trusted when only loopback is configured.
		{"loopback", "172.18.0.5:1234", false},
		{"loopback", "192.168.1.20:1234", false},
		{"loopback", "203.0.113.7:1234", false},
		{"172.18.0.0/16", "172.18.0.5:1234", true},
		{"172.18.0.0/16", "127.0.0.1:1234", false},
		{"private", "192.168.1.20:1234", true},
		{"private", "203.0.113.7:1234", false},
		// An invalid entry fails closed, even for otherwise listed peers.
		{"172.18.0.0/16, bogus", "172.18.0.5:1234", false},
		{"bogus", "127.0.0.1:1234", false},
	}
	for _, tt := range tests {
		withTrustedProxies(t, tt.proxies)
		req := httptest.NewRequest("POST", "/login", nil)
		req.RemoteAddr = tt.remote
		req.Header.Set("X-Forwarded-Proto", "https")
		if got := isSecureRequest(req); got != tt.want {
			t.Errorf("isSecureRequest(proxies=%q, remote=%s) = %v, want %v", tt.proxies, tt.remote, got, tt.want)
		}
	}
}

func TestHandleAPILogsStreamGET_RequiresSession(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/logs/stream/0", nil)
	req.SetPathValue("index", "0")
	rr := httptest.NewRecorder()
	HandleAPILogsStreamGET(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without a session, got %d", rr.Code)
	}
}

func TestDefaultTrustedProxies(t *testing.T) {
	prefixes := parseTrustedProxies(defaultTrustedProxies)
	for _, remote := range []string{"127.0.0.1", "::1", "10.1.2.3", "172.18.0.5", "192.168.1.20", "fd00::1"} {
		a, _ := parseIP(remote)
		if !isTrustedAddr(a, prefixes) {
			t.Errorf("%s should be trusted by default", remote)
		}
	}
	for _, remote := range []string{"203.0.113.7", "8.8.8.8", "2001:db8::1"} {
		a, _ := parseIP(remote)
		if isTrustedAddr(a, prefixes) {
			t.Errorf("%s must not be trusted by default", remote)
		}
	}
}

func TestParseTrustedProxies(t *testing.T) {
	prefixes := parseTrustedProxies("10.0.0.0/8, 192.0.2.10")
	if len(prefixes) != 2 {
		t.Fatalf("expected 2 prefixes, got %v", prefixes)
	}
	a, _ := parseIP("192.0.2.10:80")
	if !isTrustedAddr(a, prefixes) {
		t.Error("expected explicitly configured IP to be trusted")
	}
	b, _ := parseIP("172.18.0.5:80")
	if isTrustedAddr(b, prefixes) {
		t.Error("private address should not be trusted when TRUSTED_PROXIES is set")
	}

	if got := parseTrustedProxies("10.0.0.0/8, bogus"); got != nil {
		t.Errorf("invalid entry must fail closed, got %v", got)
	}
	if got := parseTrustedProxies("LOOPBACK"); len(got) != 2 {
		t.Errorf("loopback keyword should expand to 2 prefixes, got %v", got)
	}
	if isTrustedAddr(a, nil) {
		t.Error("an empty trust list must not trust any address")
	}
}

func TestClientIP(t *testing.T) {
	withTrustedProxies(t, "172.18.0.0/16, 10.0.0.0/8")
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.7:1234"
	req.Header.Set("X-Forwarded-For", "198.51.100.1")
	if got := clientIP(req); got != "203.0.113.7" {
		t.Errorf("untrusted peer: got %s", got)
	}

	req.RemoteAddr = "172.18.0.2:1234"
	req.Header.Set("X-Forwarded-For", "198.51.100.99, 198.51.100.1, 10.0.0.3")
	if got := clientIP(req); got != "198.51.100.1" {
		t.Errorf("trusted peer: got %s, want rightmost untrusted hop", got)
	}

	// A private peer that is not a configured proxy cannot choose its
	// throttling key through X-Forwarded-For.
	req.RemoteAddr = "192.168.1.50:1234"
	req.Header.Set("X-Forwarded-For", "198.51.100.77")
	if got := clientIP(req); got != "192.168.1.50" {
		t.Errorf("unlisted private peer: got %s, want its own address", got)
	}
}

func TestLoginLimiter(t *testing.T) {
	l := newLoginLimiter(3)
	now := time.Now()
	for i := 0; i < 2; i++ {
		if l.fail("k", now) {
			t.Fatalf("locked too early after %d failures", i+1)
		}
	}
	if !l.fail("k", now) {
		t.Fatal("expected lock after reaching the failure limit")
	}
	if l.lockedFor("k", now) <= 0 {
		t.Error("expected key to be locked")
	}
	if l.lockedFor("k", now.Add(loginMaxLockout+time.Second)) != 0 {
		t.Error("lock should expire")
	}
	l.reset("k")
	if l.lockedFor("k", now) != 0 {
		t.Error("reset should clear the lock")
	}
}

func TestHandleLoginPOST_RateLimited(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)
	defer resetLoginLimiters()

	post := func(password string) *httptest.ResponseRecorder {
		body := url.Values{"username": {"admin"}, "password": {password}}.Encode()
		req := httptest.NewRequest("POST", "/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Forwarded-Proto", "https")
		req.RemoteAddr = "127.0.0.1:12345"
		rr := httptest.NewRecorder()
		HandleLoginPOST(rr, req)
		return rr
	}

	for i := 0; i < loginMaxFailuresPerIP; i++ {
		post("wrong-password")
	}
	// Even the correct password is refused while locked out.
	if rr := post("password"); rr.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 while locked out, got %d", rr.Code)
	}
}

func TestHandleChangePasswordPOST_WrongCurrentPassword(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	body := url.Values{
		"current_password": {"not-the-password"},
		"new_password":     {"strongpassword123"},
		"confirm_password": {"strongpassword123"},
	}.Encode()
	req := makeAuthenticatedRequest(t, "POST", "/change_password", body, "admin")
	rr := httptest.NewRecorder()
	HandleChangePasswordPOST(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Current password is incorrect") {
		t.Errorf("expected rejection for wrong current password, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleChangePasswordPOST_InvalidatesOtherSessions(t *testing.T) {
	cleanup := setupTestConfig(t)
	defer cleanup()
	initTestTemplates(t)

	other := makeAuthenticatedRequest(t, "GET", "/config", "", "admin")

	body := url.Values{
		"current_password": {"password"},
		"new_password":     {"strongpassword123"},
		"confirm_password": {"strongpassword123"},
	}.Encode()
	req := makeAuthenticatedRequest(t, "POST", "/change_password", body, "admin")
	rr := httptest.NewRecorder()
	HandleChangePasswordPOST(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect after password change, got %d", rr.Code)
	}

	if _, ok := auth.GetSession(other); ok {
		t.Error("other session should be invalidated after password change")
	}
	if _, ok := auth.GetSession(req); !ok {
		t.Error("current session should stay valid after password change")
	}
}

func TestHandleUpdateServicePOST_RejectsInvalidNameAndURL(t *testing.T) {
	tests := []struct {
		name, website string
	}{
		{"evil\r\nBcc: x@example.com", "http://example.com"},
		{"svc", "file:///etc/passwd"},
		{"svc", "gopher://internal:70"},
	}
	for _, tt := range tests {
		cleanup := setupTestConfig(t)
		initTestTemplates(t)
		body := url.Values{
			"form_action":           {"update"},
			"name":                  {tt.name},
			"website_url":           {tt.website},
			"container_names":       {"c1"},
			"retries":               {"3"},
			"interval":              {"60"},
			"grace_period":          {"3600"},
			"accepted_status_codes": {"200"},
		}.Encode()
		req := makeAuthenticatedRequest(t, "POST", "/update_service/0", body, "admin")
		req.SetPathValue("index", "0")
		rr := httptest.NewRecorder()
		HandleUpdateServicePOST(rr, req)

		cfg, _ := config.LoadConfig()
		if cfg.Services[0].Name != "test-service" || cfg.Services[0].WebsiteURL != "http://example.com" {
			t.Errorf("invalid input %q / %q was saved", tt.name, tt.website)
		}
		cleanup()
	}
}

func TestProtect_RejectsCrossSitePOST(t *testing.T) {
	h := Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		site string
		want int
	}{
		{"same-origin", http.StatusOK},
		{"same-site", http.StatusForbidden},
		{"cross-site", http.StatusForbidden},
	}
	for _, tt := range tests {
		req := httptest.NewRequest("POST", "/change_password", nil)
		req.Header.Set("Sec-Fetch-Site", tt.site)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != tt.want {
			t.Errorf("Sec-Fetch-Site=%s: got %d, want %d", tt.site, rr.Code, tt.want)
		}
	}

	req := httptest.NewRequest("POST", "/change_password", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("mismatched Origin: got %d, want 403", rr.Code)
	}
	if rr.Header().Get("X-Frame-Options") != "DENY" || rr.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("expected security headers on response")
	}
}
