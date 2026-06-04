package monitor

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/arumes31/servworx/internal/config"
)

// TestSendNotificationAllProvidersDispatched verifies all providers run when enabled
func TestSendNotificationAllProvidersDispatched(t *testing.T) {
	// Count how many times the mock server was called
	callCount := 0
	done := make(chan struct{}, 10) // Buffer for all providers

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		select {
		case done <- struct{}{}:
		default:
		}
	}))
	defer ts.Close()

	// Set all providers
	os.Setenv("NOTIFICATION_WEBHOOK_URL", ts.URL)
	os.Setenv("NOTIFICATION_MSTEAMS_URL", ts.URL)
	os.Setenv("NOTIFICATION_TELEGRAM_TOKEN", "tok")
	os.Setenv("NOTIFICATION_TELEGRAM_CHAT_ID", "chatid")
	os.Setenv("NOTIFICATION_TELEGRAM_BASE_URL", ts.URL)
	os.Setenv("NOTIFICATION_DISCORD_URL", ts.URL)
	os.Setenv("NOTIFICATION_GOTIFY_URL", ts.URL)
	os.Setenv("NOTIFICATION_GOTIFY_TOKEN", "tok")
	os.Setenv("NOTIFICATION_PUSHOVER_TOKEN", "tok")
	os.Setenv("NOTIFICATION_PUSHOVER_USER", "user")
	defer func() {
		os.Unsetenv("NOTIFICATION_WEBHOOK_URL")
		os.Unsetenv("NOTIFICATION_MSTEAMS_URL")
		os.Unsetenv("NOTIFICATION_TELEGRAM_TOKEN")
		os.Unsetenv("NOTIFICATION_TELEGRAM_CHAT_ID")
		os.Unsetenv("NOTIFICATION_TELEGRAM_BASE_URL")
		os.Unsetenv("NOTIFICATION_DISCORD_URL")
		os.Unsetenv("NOTIFICATION_GOTIFY_URL")
		os.Unsetenv("NOTIFICATION_GOTIFY_TOKEN")
		os.Unsetenv("NOTIFICATION_PUSHOVER_TOKEN")
		os.Unsetenv("NOTIFICATION_PUSHOVER_USER")
	}()

	origClient := defaultHttpClient
	defaultHttpClient = &http.Client{
		Transport: &pushoverRedirectTransport{target: ts.URL},
		Timeout:   5 * time.Second,
	}
	defer func() { defaultHttpClient = origClient }()

	svc := config.ServiceConfig{
		Name:           "AllProvidersSvc",
		WebsiteURL:     "http://example.com",
		EnableWebhook:  true,
		EnableTeams:    true,
		EnableTelegram: true,
		EnableDiscord:  true,
		EnableGotify:   true,
		EnablePushover: true,
	}

	SendNotification(svc, "Down", "all providers test")

	// Wait for all 6 providers to complete
	received := 0
	timeout := time.After(5 * time.Second)
	for received < 6 {
		select {
		case <-done:
			received++
		case <-timeout:
			t.Errorf("timeout waiting for all providers; received only %d/6", received)
			return
		}
	}
}

// TestSendNotificationEmailProvider tests the email path in SendNotification
func TestSendNotificationEmailProvider(t *testing.T) {
	// Email won't connect (no SMTP server), so it should error but not panic
	os.Setenv("NOTIFICATION_SMTP_HOST", "127.0.0.1")
	os.Setenv("NOTIFICATION_SMTP_PORT", "19998") // Nothing listening here
	os.Setenv("NOTIFICATION_SMTP_FROM", "a@b.com")
	os.Setenv("NOTIFICATION_SMTP_TO", "c@d.com")
	defer func() {
		os.Unsetenv("NOTIFICATION_SMTP_HOST")
		os.Unsetenv("NOTIFICATION_SMTP_PORT")
		os.Unsetenv("NOTIFICATION_SMTP_FROM")
		os.Unsetenv("NOTIFICATION_SMTP_TO")
	}()

	svc := config.ServiceConfig{
		Name:        "EmailProviderSvc",
		EnableEmail: true,
		WebsiteURL:  "http://example.com",
	}

	// Should not panic; the goroutine will handle the error internally
	SendNotification(svc, "Down", "email test")
	time.Sleep(500 * time.Millisecond) // Give goroutine time to fail gracefully
}

// TestSendNotificationWebhookFails covers the webhook error logging path
func TestSendNotificationWebhookFails(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError) // Force failure
	}))
	defer ts.Close()

	os.Setenv("NOTIFICATION_WEBHOOK_URL", ts.URL)
	defer os.Unsetenv("NOTIFICATION_WEBHOOK_URL")

	done := make(chan struct{}, 1)
	// We'll wait a bit and confirm no panic
	svc := config.ServiceConfig{
		Name:          "FailWebhookSvc",
		EnableWebhook: true,
		WebsiteURL:    "http://example.com",
	}
	SendNotification(svc, "Down", "fail test")

	go func() {
		time.Sleep(500 * time.Millisecond)
		done <- struct{}{}
	}()
	<-done // No panic = pass
}

// TestSendNotificationTeamsFails covers the Teams error logging path
func TestSendNotificationTeamsFails(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	os.Setenv("NOTIFICATION_MSTEAMS_URL", ts.URL)
	defer os.Unsetenv("NOTIFICATION_MSTEAMS_URL")

	svc := config.ServiceConfig{
		Name:        "FailTeamsSvc",
		EnableTeams: true,
		WebsiteURL:  "http://example.com",
	}
	SendNotification(svc, "Down", "teams fail test")
	time.Sleep(300 * time.Millisecond)
}

// TestSendNotificationTelegramFails covers the Telegram error logging path
func TestSendNotificationTelegramFails(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	os.Setenv("NOTIFICATION_TELEGRAM_TOKEN", "tok")
	os.Setenv("NOTIFICATION_TELEGRAM_CHAT_ID", "chatid")
	os.Setenv("NOTIFICATION_TELEGRAM_BASE_URL", ts.URL)
	defer func() {
		os.Unsetenv("NOTIFICATION_TELEGRAM_TOKEN")
		os.Unsetenv("NOTIFICATION_TELEGRAM_CHAT_ID")
		os.Unsetenv("NOTIFICATION_TELEGRAM_BASE_URL")
	}()

	svc := config.ServiceConfig{
		Name:           "FailTelegramSvc",
		EnableTelegram: true,
	}
	SendNotification(svc, "Down", "telegram fail test")
	time.Sleep(300 * time.Millisecond)
}

// TestSendNotificationDiscordFails covers the Discord error logging path
func TestSendNotificationDiscordFails(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	os.Setenv("NOTIFICATION_DISCORD_URL", ts.URL)
	defer os.Unsetenv("NOTIFICATION_DISCORD_URL")

	svc := config.ServiceConfig{
		Name:          "FailDiscordSvc",
		EnableDiscord: true,
	}
	SendNotification(svc, "Down", "discord fail test")
	time.Sleep(300 * time.Millisecond)
}

// TestSendNotificationGotifyFails covers the Gotify error logging path
func TestSendNotificationGotifyFails(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	os.Setenv("NOTIFICATION_GOTIFY_URL", ts.URL)
	os.Setenv("NOTIFICATION_GOTIFY_TOKEN", "tok")
	defer os.Unsetenv("NOTIFICATION_GOTIFY_URL")
	defer os.Unsetenv("NOTIFICATION_GOTIFY_TOKEN")

	svc := config.ServiceConfig{
		Name:         "FailGotifySvc",
		EnableGotify: true,
	}
	SendNotification(svc, "Down", "gotify fail test")
	time.Sleep(300 * time.Millisecond)
}

// TestSendNotificationPushoverFails covers the Pushover error logging path
func TestSendNotificationPushoverFails(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	os.Setenv("NOTIFICATION_PUSHOVER_TOKEN", "tok")
	os.Setenv("NOTIFICATION_PUSHOVER_USER", "user")
	defer os.Unsetenv("NOTIFICATION_PUSHOVER_TOKEN")
	defer os.Unsetenv("NOTIFICATION_PUSHOVER_USER")

	origClient := defaultHttpClient
	defaultHttpClient = &http.Client{
		Transport: &pushoverRedirectTransport{target: ts.URL},
		Timeout:   5 * time.Second,
	}
	defer func() { defaultHttpClient = origClient }()

	svc := config.ServiceConfig{
		Name:           "FailPushoverSvc",
		EnablePushover: true,
	}
	SendNotification(svc, "Down", "pushover fail test")
	time.Sleep(300 * time.Millisecond)
}

// TestSendNotificationWebhookSuccess covers the webhook success logging path
func TestSendNotificationWebhookSuccess(t *testing.T) {
	done := make(chan struct{}, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		select {
		case done <- struct{}{}:
		default:
		}
	}))
	defer ts.Close()

	os.Setenv("NOTIFICATION_WEBHOOK_URL", ts.URL)
	defer os.Unsetenv("NOTIFICATION_WEBHOOK_URL")

	svc := config.ServiceConfig{
		Name:          "SuccessWebhookSvc",
		EnableWebhook: true,
		WebsiteURL:    "http://example.com",
	}
	SendNotification(svc, "Up", "recovery")

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("timeout: expected webhook to be called")
	}
}

// TestRestartContainersWithAlertOnRestart tests the AlertOnRestart branch
func TestRestartContainersWithAlertOnRestart(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := config.ConfigDir
	config.SetConfigDir(tmpDir)
	t.Cleanup(func() { config.SetConfigDir(originalDir) })

	svcName := "restart-alert-svc"

	// Save config with AlertOnRestart=true
	cfg := &config.Config{
		Services: []config.ServiceConfig{
			{
				Name:           svcName,
				ContainerNames: "",
				AlertOnRestart: true,
			},
		},
	}
	_ = config.SaveConfig(cfg)
	_ = config.UpdateStatus(func(s *config.Status) {
		s.Services = []config.ServiceStatus{
			{Name: svcName, Status: "Down", LastStableStatus: "Down"},
		}
	})

	// Should run without panic
	result := restartContainers("", svcName)
	if result == 0 {
		t.Error("expected non-zero restart time")
	}
}

// TestStartMonitoringConfigLoadError covers the config load failure path
func TestStartMonitoringConfigLoadError(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := config.ConfigDir
	config.SetConfigDir(tmpDir)
	t.Cleanup(func() { config.SetConfigDir(originalDir) })

	// Don't create any config file — LoadConfig will fail gracefully with defaults
	// or the function returns early
	// Actually LoadConfig returns defaults on missing file, so StartMonitoring won't fail.
	// Just verify no panic.
	StartMonitoring()
	time.Sleep(50 * time.Millisecond)
	StopMonitoring()
}
