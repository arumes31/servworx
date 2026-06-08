package monitor

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/arumes31/servworx/internal/config"
)

// pushoverRedirectTransport redirects the hardcoded pushover URL to our test server
type pushoverRedirectTransport struct {
	target string
}

func (p *pushoverRedirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	targetURL, _ := url.Parse(p.target)
	req.URL.Scheme = targetURL.Scheme
	req.URL.Host = targetURL.Host
	req.Host = targetURL.Host
	return http.DefaultTransport.RoundTrip(req)
}

// TestSendPushover verifies Pushover sends a form POST with correct fields
func TestSendPushover(t *testing.T) {
	var receivedForm url.Values

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedForm, _ = url.ParseQuery(string(body))
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	_ = os.Setenv("NOTIFICATION_PUSHOVER_TOKEN", "test-token-abc")
	_ = os.Setenv("NOTIFICATION_PUSHOVER_USER", "test-user-xyz")
	defer func() { _ = os.Unsetenv("NOTIFICATION_PUSHOVER_TOKEN") }()
	defer func() { _ = os.Unsetenv("NOTIFICATION_PUSHOVER_USER") }()

	origClient := defaultHttpClient
	defaultHttpClient = &http.Client{
		Transport: &pushoverRedirectTransport{target: ts.URL},
		Timeout:   5 * time.Second,
	}
	defer func() { defaultHttpClient = origClient }()

	svc := config.ServiceConfig{
		Name:           "PushoverTestService",
		WebsiteURL:     "http://example.com",
		ContainerNames: "web",
	}

	err := sendPushover(svc, "Down", "Service is unreachable.")
	if err != nil {
		t.Fatalf("sendPushover failed: %v", err)
	}

	if receivedForm.Get("token") != "test-token-abc" {
		t.Errorf("expected token test-token-abc, got %s", receivedForm.Get("token"))
	}
	if receivedForm.Get("user") != "test-user-xyz" {
		t.Errorf("expected user test-user-xyz, got %s", receivedForm.Get("user"))
	}
	if !strings.Contains(receivedForm.Get("title"), "PushoverTestService") {
		t.Errorf("expected title to contain service name, got: %s", receivedForm.Get("title"))
	}
	if receivedForm.Get("priority") != "1" {
		t.Errorf("expected priority 1 for Down, got %s", receivedForm.Get("priority"))
	}
}

// TestSendPushoverUpStatus verifies the Up status sends priority=0
func TestSendPushoverUpStatus(t *testing.T) {
	var receivedForm url.Values
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedForm, _ = url.ParseQuery(string(body))
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	_ = os.Setenv("NOTIFICATION_PUSHOVER_TOKEN", "tok")
	_ = os.Setenv("NOTIFICATION_PUSHOVER_USER", "usr")
	defer func() { _ = os.Unsetenv("NOTIFICATION_PUSHOVER_TOKEN") }()
	defer func() { _ = os.Unsetenv("NOTIFICATION_PUSHOVER_USER") }()

	origClient := defaultHttpClient
	defaultHttpClient = &http.Client{
		Transport: &pushoverRedirectTransport{target: ts.URL},
		Timeout:   5 * time.Second,
	}
	defer func() { defaultHttpClient = origClient }()

	svc := config.ServiceConfig{Name: "SvcUp"}
	err := sendPushover(svc, "Up", "Recovered.")
	if err != nil {
		t.Fatalf("sendPushover Up failed: %v", err)
	}
	if receivedForm.Get("priority") != "0" {
		t.Errorf("expected priority 0 for Up, got %s", receivedForm.Get("priority"))
	}
}

// TestSendPushoverNon2xx verifies non-2xx response is treated as error
func TestSendPushoverNon2xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	_ = os.Setenv("NOTIFICATION_PUSHOVER_TOKEN", "tok")
	_ = os.Setenv("NOTIFICATION_PUSHOVER_USER", "usr")
	defer func() { _ = os.Unsetenv("NOTIFICATION_PUSHOVER_TOKEN") }()
	defer func() { _ = os.Unsetenv("NOTIFICATION_PUSHOVER_USER") }()

	origClient := defaultHttpClient
	defaultHttpClient = &http.Client{
		Transport: &pushoverRedirectTransport{target: ts.URL},
		Timeout:   5 * time.Second,
	}
	defer func() { defaultHttpClient = origClient }()

	svc := config.ServiceConfig{Name: "PushoverBad"}
	err := sendPushover(svc, "Down", "Err")
	if err == nil {
		t.Error("expected error for non-2xx pushover response")
	}
}

// TestSendTestNotificationAllProviders exercises every provider case
func TestSendTestNotificationAllProviders(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	_ = os.Setenv("NOTIFICATION_WEBHOOK_URL", ts.URL)
	_ = os.Setenv("NOTIFICATION_MSTEAMS_URL", ts.URL)
	_ = os.Setenv("NOTIFICATION_TELEGRAM_TOKEN", "tok")
	_ = os.Setenv("NOTIFICATION_TELEGRAM_CHAT_ID", "chatid")
	_ = os.Setenv("NOTIFICATION_TELEGRAM_BASE_URL", ts.URL)
	_ = os.Setenv("NOTIFICATION_DISCORD_URL", ts.URL)
	_ = os.Setenv("NOTIFICATION_GOTIFY_URL", ts.URL)
	_ = os.Setenv("NOTIFICATION_GOTIFY_TOKEN", "tok")
	_ = os.Setenv("NOTIFICATION_PUSHOVER_TOKEN", "tok")
	_ = os.Setenv("NOTIFICATION_PUSHOVER_USER", "user")
	defer func() {
		_ = os.Unsetenv("NOTIFICATION_WEBHOOK_URL")
		_ = os.Unsetenv("NOTIFICATION_MSTEAMS_URL")
		_ = os.Unsetenv("NOTIFICATION_TELEGRAM_TOKEN")
		_ = os.Unsetenv("NOTIFICATION_TELEGRAM_CHAT_ID")
		_ = os.Unsetenv("NOTIFICATION_TELEGRAM_BASE_URL")
		_ = os.Unsetenv("NOTIFICATION_DISCORD_URL")
		_ = os.Unsetenv("NOTIFICATION_GOTIFY_URL")
		_ = os.Unsetenv("NOTIFICATION_GOTIFY_TOKEN")
		_ = os.Unsetenv("NOTIFICATION_PUSHOVER_TOKEN")
		_ = os.Unsetenv("NOTIFICATION_PUSHOVER_USER")
	}()

	origClient := defaultHttpClient
	defaultHttpClient = &http.Client{
		Transport: &pushoverRedirectTransport{target: ts.URL},
		Timeout:   5 * time.Second,
	}
	defer func() { defaultHttpClient = origClient }()

	svc := config.ServiceConfig{
		Name:       "TestSvc",
		WebsiteURL: "http://example.com",
	}

	providers := []string{"webhook", "teams", "telegram", "discord", "gotify", "pushover"}
	for _, p := range providers {
		t.Run(p, func(t *testing.T) {
			err := SendTestNotification(svc, p)
			if err != nil {
				t.Errorf("SendTestNotification(%s) failed: %v", p, err)
			}
		})
	}
}

// TestSendTestNotificationEmail tests email provider via SendTestNotification (missing config)
func TestSendTestNotificationEmail(t *testing.T) {
	_ = os.Unsetenv("NOTIFICATION_SMTP_HOST")
	_ = os.Unsetenv("NOTIFICATION_SMTP_PORT")
	_ = os.Unsetenv("NOTIFICATION_SMTP_FROM")
	_ = os.Unsetenv("NOTIFICATION_SMTP_TO")

	svc := config.ServiceConfig{Name: "EmailTestSvc"}
	err := SendTestNotification(svc, "email")
	if err == nil {
		t.Error("expected error for email with missing SMTP config")
	}
}

// TestSendTestNotificationUnknownProvider checks the default error path
func TestSendTestNotificationUnknownProvider(t *testing.T) {
	svc := config.ServiceConfig{Name: "Svc"}
	err := SendTestNotification(svc, "slack")
	if err == nil {
		t.Error("expected error for unknown provider 'slack'")
	}
	if !strings.Contains(err.Error(), "unknown notification provider") {
		t.Errorf("expected 'unknown notification provider' in error, got: %v", err)
	}
}

// TestSendNotificationSnoozed verifies snoozed services skip notification
func TestSendNotificationSnoozed(t *testing.T) {
	var called bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	_ = os.Setenv("NOTIFICATION_WEBHOOK_URL", ts.URL)
	defer func() { _ = os.Unsetenv("NOTIFICATION_WEBHOOK_URL") }()

	svc := config.ServiceConfig{
		Name:             "SnoozedSvc",
		EnableWebhook:    true,
		AlertSnoozeUntil: time.Now().Unix() + 3600,
	}

	SendNotification(svc, "Down", "service down")
	time.Sleep(100 * time.Millisecond)

	if called {
		t.Error("expected webhook NOT to be called when service is snoozed")
	}
}

// TestSendNotificationQuietHours verifies quiet hours skip notification
func TestSendNotificationQuietHours(t *testing.T) {
	var called bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	_ = os.Setenv("NOTIFICATION_WEBHOOK_URL", ts.URL)
	defer func() { _ = os.Unsetenv("NOTIFICATION_WEBHOOK_URL") }()

	svc := config.ServiceConfig{
		Name:            "QuietSvc",
		EnableWebhook:   true,
		QuietHoursStart: "00:00",
		QuietHoursEnd:   "23:59",
	}

	SendNotification(svc, "Down", "service down")
	time.Sleep(100 * time.Millisecond)

	if called {
		t.Error("expected webhook NOT to be called during quiet hours")
	}
}

// TestSendNotificationDispatches verifies active notifications are dispatched
func TestSendNotificationDispatches(t *testing.T) {
	done := make(chan struct{}, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		select {
		case done <- struct{}{}:
		default:
		}
	}))
	defer ts.Close()

	_ = os.Setenv("NOTIFICATION_WEBHOOK_URL", ts.URL)
	defer func() { _ = os.Unsetenv("NOTIFICATION_WEBHOOK_URL") }()

	svc := config.ServiceConfig{
		Name:          "ActiveSvc",
		EnableWebhook: true,
		WebsiteURL:    "http://example.com",
	}

	SendNotification(svc, "Down", "service down")

	select {
	case <-done:
		// Success
	case <-time.After(3 * time.Second):
		t.Error("expected webhook to be called within 3 seconds")
	}
}

// TestIsQuietHoursOvernight covers wrap-around ranges
func TestIsQuietHoursOvernight(t *testing.T) {
	now, _ := time.Parse("15:04", "23:30")
	result1 := isQuietHours(now, "23:00", "01:00")
	now2, _ := time.Parse("15:04", "12:00")
	result2 := isQuietHours(now2, "01:00", "23:00")
	if !result1 {
		t.Error("expected true for 23:30 in 23:00-01:00")
	}
	if !result2 {
		t.Error("expected true for 12:00 in 01:00-23:00")
	}
}

// TestSendWebhookMissingConfig verifies error when env var is missing
func TestSendWebhookMissingConfig(t *testing.T) {
	_ = os.Unsetenv("NOTIFICATION_WEBHOOK_URL")
	svc := config.ServiceConfig{Name: "WH"}
	err := sendWebhook(svc, "Down", "test")
	if err == nil {
		t.Error("expected error for missing webhook URL")
	}
}

// TestSendTeamsMissingConfig verifies error when env var is missing
func TestSendTeamsMissingConfig(t *testing.T) {
	_ = os.Unsetenv("NOTIFICATION_MSTEAMS_URL")
	svc := config.ServiceConfig{Name: "Teams"}
	err := sendTeams(svc, "Down", "test")
	if err == nil {
		t.Error("expected error for missing Teams URL")
	}
}

// TestSendDiscordMissingConfig verifies error when env var is missing
func TestSendDiscordMissingConfig(t *testing.T) {
	_ = os.Unsetenv("NOTIFICATION_DISCORD_URL")
	svc := config.ServiceConfig{Name: "Discord"}
	err := sendDiscord(svc, "Down", "test")
	if err == nil {
		t.Error("expected error for missing Discord URL")
	}
}

// TestSendGotifyMissingConfig verifies error when env var is missing
func TestSendGotifyMissingConfig(t *testing.T) {
	_ = os.Unsetenv("NOTIFICATION_GOTIFY_URL")
	_ = os.Unsetenv("NOTIFICATION_GOTIFY_TOKEN")
	svc := config.ServiceConfig{Name: "Gotify"}
	err := sendGotify(svc, "Down", "test")
	if err == nil {
		t.Error("expected error for missing Gotify config")
	}
}

// TestSendEmailMissingConfig verifies error when SMTP env is missing
func TestSendEmailMissingConfig(t *testing.T) {
	_ = os.Unsetenv("NOTIFICATION_SMTP_HOST")
	_ = os.Unsetenv("NOTIFICATION_SMTP_PORT")
	_ = os.Unsetenv("NOTIFICATION_SMTP_FROM")
	_ = os.Unsetenv("NOTIFICATION_SMTP_TO")
	svc := config.ServiceConfig{Name: "Email"}
	err := sendEmail(svc, "Down", "test")
	if err == nil {
		t.Error("expected error for missing SMTP config")
	}
}

// TestSendEmailInvalidPort verifies error when SMTP port is not a number
func TestSendEmailInvalidPort(t *testing.T) {
	_ = os.Setenv("NOTIFICATION_SMTP_HOST", "localhost")
	_ = os.Setenv("NOTIFICATION_SMTP_PORT", "notanumber")
	_ = os.Setenv("NOTIFICATION_SMTP_FROM", "a@b.com")
	_ = os.Setenv("NOTIFICATION_SMTP_TO", "c@d.com")
	defer func() {
		_ = os.Unsetenv("NOTIFICATION_SMTP_HOST")
		_ = os.Unsetenv("NOTIFICATION_SMTP_PORT")
		_ = os.Unsetenv("NOTIFICATION_SMTP_FROM")
		_ = os.Unsetenv("NOTIFICATION_SMTP_TO")
	}()
	svc := config.ServiceConfig{Name: "Email"}
	err := sendEmail(svc, "Down", "test")
	if err == nil {
		t.Error("expected error for invalid SMTP port")
	}
}

// TestSendWebhookNon2xx verifies non-2xx webhook response is an error
func TestSendWebhookNon2xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	_ = os.Setenv("NOTIFICATION_WEBHOOK_URL", ts.URL)
	defer func() { _ = os.Unsetenv("NOTIFICATION_WEBHOOK_URL") }()

	svc := config.ServiceConfig{Name: "WH"}
	err := sendWebhook(svc, "Down", "test")
	if err == nil {
		t.Error("expected error for 500 webhook response")
	}
}

// TestSendTeamsNon2xx verifies non-2xx Teams response is an error
func TestSendTeamsNon2xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	_ = os.Setenv("NOTIFICATION_MSTEAMS_URL", ts.URL)
	defer func() { _ = os.Unsetenv("NOTIFICATION_MSTEAMS_URL") }()

	svc := config.ServiceConfig{Name: "Teams"}
	err := sendTeams(svc, "Down", "test")
	if err == nil {
		t.Error("expected error for non-2xx Teams response")
	}
}

// TestSendTeamsUpStatus verifies green color for Up status
func TestSendTeamsUpStatus(t *testing.T) {
	var receivedPayload map[string]interface{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	_ = os.Setenv("NOTIFICATION_MSTEAMS_URL", ts.URL)
	defer func() { _ = os.Unsetenv("NOTIFICATION_MSTEAMS_URL") }()

	svc := config.ServiceConfig{Name: "TeamsUp", WebsiteURL: "http://ex.com", ContainerNames: "web"}
	err := sendTeams(svc, "Up", "Recovered!")
	if err != nil {
		t.Fatalf("sendTeams Up failed: %v", err)
	}
	if receivedPayload["themeColor"] != "00FF00" {
		t.Errorf("expected green themeColor for Up, got %v", receivedPayload["themeColor"])
	}
}

// TestSendDiscordUpStatus verifies green color for Up status in Discord embed
func TestSendDiscordUpStatus(t *testing.T) {
	var receivedPayload map[string]interface{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedPayload)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	_ = os.Setenv("NOTIFICATION_DISCORD_URL", ts.URL)
	defer func() { _ = os.Unsetenv("NOTIFICATION_DISCORD_URL") }()

	svc := config.ServiceConfig{Name: "DiscordUp", WebsiteURL: "http://ex.com", ContainerNames: "web"}
	err := sendDiscord(svc, "Up", "Recovered!")
	if err != nil {
		t.Fatalf("sendDiscord Up failed: %v", err)
	}
	embeds := receivedPayload["embeds"].([]interface{})
	embed := embeds[0].(map[string]interface{})
	colorVal := embed["color"].(float64)
	if colorVal != 65280 { // 0x00FF00 = 65280
		t.Errorf("expected color 65280 for Up, got %v", colorVal)
	}
}

// TestSendGotifyUpStatus verifies lower priority for Up status in Gotify
func TestSendGotifyUpStatus(t *testing.T) {
	var receivedPayload map[string]interface{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	_ = os.Setenv("NOTIFICATION_GOTIFY_URL", ts.URL)
	_ = os.Setenv("NOTIFICATION_GOTIFY_TOKEN", "tok")
	defer func() { _ = os.Unsetenv("NOTIFICATION_GOTIFY_URL") }()
	defer func() { _ = os.Unsetenv("NOTIFICATION_GOTIFY_TOKEN") }()

	svc := config.ServiceConfig{Name: "GotifyUp"}
	err := sendGotify(svc, "Up", "Recovered!")
	if err != nil {
		t.Fatalf("sendGotify Up failed: %v", err)
	}
	priority := receivedPayload["priority"].(float64)
	if priority != 5 {
		t.Errorf("expected priority 5 for Up, got %v", priority)
	}
}

// TestSendGotifyNon2xx verifies non-2xx Gotify response is an error
func TestSendGotifyNon2xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	_ = os.Setenv("NOTIFICATION_GOTIFY_URL", ts.URL)
	_ = os.Setenv("NOTIFICATION_GOTIFY_TOKEN", "bad-tok")
	defer func() { _ = os.Unsetenv("NOTIFICATION_GOTIFY_URL") }()
	defer func() { _ = os.Unsetenv("NOTIFICATION_GOTIFY_TOKEN") }()

	svc := config.ServiceConfig{Name: "GotifyBad"}
	err := sendGotify(svc, "Down", "test")
	if err == nil {
		t.Error("expected error for 401 Gotify response")
	}
}

// TestSendDiscordNon2xx verifies non-2xx Discord response is an error
func TestSendDiscordNon2xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer ts.Close()

	_ = os.Setenv("NOTIFICATION_DISCORD_URL", ts.URL)
	defer func() { _ = os.Unsetenv("NOTIFICATION_DISCORD_URL") }()

	svc := config.ServiceConfig{Name: "DiscordBad"}
	err := sendDiscord(svc, "Down", "test")
	if err == nil {
		t.Error("expected error for non-2xx Discord response")
	}
}

// TestSendTelegramNon2xx verifies non-2xx Telegram response is an error
func TestSendTelegramNon2xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	_ = os.Setenv("NOTIFICATION_TELEGRAM_TOKEN", "tok")
	_ = os.Setenv("NOTIFICATION_TELEGRAM_CHAT_ID", "chatid")
	_ = os.Setenv("NOTIFICATION_TELEGRAM_BASE_URL", ts.URL)
	defer func() {
		_ = os.Unsetenv("NOTIFICATION_TELEGRAM_TOKEN")
		_ = os.Unsetenv("NOTIFICATION_TELEGRAM_CHAT_ID")
		_ = os.Unsetenv("NOTIFICATION_TELEGRAM_BASE_URL")
	}()

	svc := config.ServiceConfig{Name: "TgBad"}
	err := sendTelegram(svc, "Down", "test")
	if err == nil {
		t.Error("expected error for non-2xx Telegram response")
	}
}
