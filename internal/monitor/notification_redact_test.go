package monitor

import (
	"strings"
	"testing"

	"github.com/arumes31/servworx/internal/config"
)

// TestSendersRedactCredentialURLs verifies that transport errors from the
// HTTP-based providers never echo the credential-bearing request URL.
func TestSendersRedactCredentialURLs(t *testing.T) {
	const secret = "SUPERSECRETTOKEN"
	// Port 1 on loopback is closed, so Do fails with a *url.Error.
	closed := "http://127.0.0.1:1"
	svc := config.ServiceConfig{Name: "svc"}

	cases := []struct {
		name string
		env  map[string]string
		send func() error
	}{
		{"webhook", map[string]string{"NOTIFICATION_WEBHOOK_URL": closed + "/hook/" + secret}, func() error { return sendWebhook(svc, "Down", "d") }},
		{"teams", map[string]string{"NOTIFICATION_MSTEAMS_URL": closed + "/webhookb2/" + secret}, func() error { return sendTeams(svc, "Down", "d") }},
		{"discord", map[string]string{"NOTIFICATION_DISCORD_URL": closed + "/api/webhooks/1/" + secret}, func() error { return sendDiscord(svc, "Down", "d") }},
		{"gotify", map[string]string{"NOTIFICATION_GOTIFY_URL": closed, "NOTIFICATION_GOTIFY_TOKEN": secret}, func() error { return sendGotify(svc, "Down", "d") }},
		{"telegram", map[string]string{"NOTIFICATION_TELEGRAM_TOKEN": secret, "NOTIFICATION_TELEGRAM_CHAT_ID": "1", "NOTIFICATION_TELEGRAM_BASE_URL": closed}, func() error { return sendTelegram(svc, "Down", "d") }},
		{"webhook invalid url", map[string]string{"NOTIFICATION_WEBHOOK_URL": "http://[::1" + secret}, func() error { return sendWebhook(svc, "Down", "d") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			err := tc.send()
			if err == nil {
				t.Fatal("expected an error")
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error leaks credential: %v", err)
			}
			if strings.HasSuffix(tc.name, "invalid url") && !strings.Contains(err.Error(), "invalid URL") {
				t.Errorf("parse failure not labelled as invalid URL: %v", err)
			}
		})
	}
}
