package monitor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/arumes31/servworx/internal/config"
)

// isQuietHours checks if the current time falls inside the configured start and end hour range.
func isQuietHours(now time.Time, start, end string) bool {
	if start == "" || end == "" {
		return false
	}
	nowHM := now.Format("15:04")
	if start < end {
		return nowHM >= start && nowHM <= end
	}
	return nowHM >= start || nowHM <= end
}

// SendNotification dispatches asynchronous alerts over enabled channels on status transitions
func SendNotification(svc config.ServiceConfig, status string, detailMessage string) {
	// Execute Quiet Hours and Snooze checks
	if status != "Up" || (status == "Up" && !svc.AlertOnRecovery) {
		if svc.AlertSnoozeUntil > time.Now().Unix() {
			LogAction("System", fmt.Sprintf("Alerts for service %s are currently snoozed. Skipping notification.", svc.Name), "system")
			return
		}
		if isQuietHours(time.Now(), svc.QuietHoursStart, svc.QuietHoursEnd) {
			LogAction("System", fmt.Sprintf("Alerts for service %s are in Quiet Hours (%s to %s). Skipping notification.", svc.Name, svc.QuietHoursStart, svc.QuietHoursEnd), "system")
			return
		}
	}

	// Execute asynchronously in a goroutine so it never blocks the health check loop
	go func() {
		LogAction("System", fmt.Sprintf("Dispatching %s status alerts for service %s...", status, svc.Name), "system")

		if svc.EnableWebhook {
			if err := sendWebhook(svc, status, detailMessage); err != nil {
				LogAction("System", fmt.Sprintf("Webhook alert failed for %s: %v", svc.Name, err), "error")
			} else {
				LogAction("System", fmt.Sprintf("Webhook alert successfully sent for %s", svc.Name), "system")
			}
		}

		if svc.EnableTeams {
			if err := sendTeams(svc, status, detailMessage); err != nil {
				LogAction("System", fmt.Sprintf("MS Teams alert failed for %s: %v", svc.Name, err), "error")
			} else {
				LogAction("System", fmt.Sprintf("MS Teams alert successfully sent for %s", svc.Name), "system")
			}
		}

		if svc.EnableTelegram {
			if err := sendTelegram(svc, status, detailMessage); err != nil {
				LogAction("System", fmt.Sprintf("Telegram alert failed for %s: %v", svc.Name, err), "error")
			} else {
				LogAction("System", fmt.Sprintf("Telegram alert successfully sent for %s", svc.Name), "system")
			}
		}

		if svc.EnableEmail {
			if err := sendEmail(svc, status, detailMessage); err != nil {
				LogAction("System", fmt.Sprintf("Email alert failed for %s: %v", svc.Name, err), "error")
			} else {
				LogAction("System", fmt.Sprintf("Email alert successfully sent for %s", svc.Name), "system")
			}
		}

		if svc.EnableDiscord {
			if err := sendDiscord(svc, status, detailMessage); err != nil {
				LogAction("System", fmt.Sprintf("Discord alert failed for %s: %v", svc.Name, err), "error")
			} else {
				LogAction("System", fmt.Sprintf("Discord alert successfully sent for %s", svc.Name), "system")
			}
		}

		if svc.EnableGotify {
			if err := sendGotify(svc, status, detailMessage); err != nil {
				LogAction("System", fmt.Sprintf("Gotify alert failed for %s: %v", svc.Name, err), "error")
			} else {
				LogAction("System", fmt.Sprintf("Gotify alert successfully sent for %s", svc.Name), "system")
			}
		}

		if svc.EnablePushover {
			if err := sendPushover(svc, status, detailMessage); err != nil {
				LogAction("System", fmt.Sprintf("Pushover alert failed for %s: %v", svc.Name, err), "error")
			} else {
				LogAction("System", fmt.Sprintf("Pushover alert successfully sent for %s", svc.Name), "system")
			}
		}
	}()
}

type WebhookPayload struct {
	Service   string `json:"service"`
	URL       string `json:"url"`
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
	Message   string `json:"message"`
}

func sendWebhook(svc config.ServiceConfig, status string, detail string) error {
	webhookURL := os.Getenv("NOTIFICATION_WEBHOOK_URL")
	if webhookURL == "" {
		return fmt.Errorf("NOTIFICATION_WEBHOOK_URL is not configured in environment")
	}

	payload := WebhookPayload{
		Service:   svc.Name,
		URL:       svc.WebsiteURL,
		Status:    status,
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		Message:   detail,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// #nosec G107 G704
	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	// #nosec G704
	resp, err := defaultHttpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook responded with non-2xx status: %d", resp.StatusCode)
	}
	return nil
}

func sendTeams(svc config.ServiceConfig, status string, detail string) error {
	teamsURL := os.Getenv("NOTIFICATION_MSTEAMS_URL")
	if teamsURL == "" {
		return fmt.Errorf("NOTIFICATION_MSTEAMS_URL is not configured in environment")
	}

	color := "FF0000" // Red for Down
	emoji := "🚨"
	if status == "Up" {
		color = "00FF00" // Green for Up
		emoji = "✅"
	}

	card := map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"themeColor": color,
		"summary":    fmt.Sprintf("servworx Alert: %s is %s", svc.Name, status),
		"title":      fmt.Sprintf("%s Service %s: %s", emoji, status, svc.Name),
		"text": fmt.Sprintf("Service **%s** (%s) is now **%s**.<br><br>**Detail:** %s<br>**Containers Managed:** %s",
			svc.Name, svc.WebsiteURL, status, detail, svc.ContainerNames),
	}

	data, err := json.Marshal(card)
	if err != nil {
		return err
	}

	// #nosec G107 G704
	req, err := http.NewRequest("POST", teamsURL, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	// #nosec G704
	resp, err := defaultHttpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ms teams webhook responded with non-2xx status: %d", resp.StatusCode)
	}
	return nil
}

func sendTelegram(svc config.ServiceConfig, status string, detail string) error {
	token := os.Getenv("NOTIFICATION_TELEGRAM_TOKEN")
	chatID := os.Getenv("NOTIFICATION_TELEGRAM_CHAT_ID")
	if token == "" || chatID == "" {
		return fmt.Errorf("NOTIFICATION_TELEGRAM_TOKEN or NOTIFICATION_TELEGRAM_CHAT_ID is not configured in environment")
	}

	emoji := "🚨"
	if status == "Up" {
		emoji = "✅"
	}

	text := fmt.Sprintf("%s *servworx Alert*\n\n*Service:* %s\n*URL:* %s\n*Status:* %s\n\n*Detail:* %s\n*Containers:* `%s`",
		emoji, svc.Name, svc.WebsiteURL, strings.ToUpper(status), detail, svc.ContainerNames)

	payload := map[string]interface{}{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "Markdown",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	baseURL := os.Getenv("NOTIFICATION_TELEGRAM_BASE_URL")
	if baseURL == "" {
		baseURL = "https://api.telegram.org"
	}
	telegramURL := fmt.Sprintf("%s/bot%s/sendMessage", baseURL, token)
	// #nosec G107 G704
	req, err := http.NewRequest("POST", telegramURL, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("telegram request creation failed")
	}
	req.Header.Set("Content-Type", "application/json")

	// #nosec G704
	resp, err := defaultHttpClient.Do(req)
	if err != nil {
		// Sanitize error to prevent leaking the bot token from *url.Error
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			return fmt.Errorf("telegram api request failed: connection error")
		}
		return fmt.Errorf("telegram api request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("telegram api responded with non-2xx status: %d", resp.StatusCode)
	}
	return nil
}

func sendEmail(svc config.ServiceConfig, status string, detail string) error {
	host := os.Getenv("NOTIFICATION_SMTP_HOST")
	portStr := os.Getenv("NOTIFICATION_SMTP_PORT")
	user := os.Getenv("NOTIFICATION_SMTP_USER")
	pass := os.Getenv("NOTIFICATION_SMTP_PASS")
	from := os.Getenv("NOTIFICATION_SMTP_FROM")
	to := os.Getenv("NOTIFICATION_SMTP_TO")

	if host == "" || portStr == "" || from == "" || to == "" {
		return fmt.Errorf("NOTIFICATION_SMTP_HOST, PORT, FROM, or TO is not configured in environment")
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid NOTIFICATION_SMTP_PORT: %v", err)
	}

	emoji := "🚨"
	if status == "Up" {
		emoji = "✅"
	}

	subject := fmt.Sprintf("Subject: [servworx] %s Service %s: %s\n", emoji, status, svc.Name)
	mime := "MIME-Version: 1.0;\nContent-Type: text/plain; charset=UTF-8;\n"
	headers := fmt.Sprintf("From: %s\nTo: %s\n%s%s\n", from, to, mime, subject)
	body := fmt.Sprintf("Service: %s (%s)\nStatus: %s\n\nDetail: %s\nContainers: %s\nTimestamp: %s\n",
		svc.Name, svc.WebsiteURL, status, detail, svc.ContainerNames, time.Now().Format("2006-01-02 15:04:05"))

	message := []byte(headers + body)

	addr := fmt.Sprintf("%s:%d", host, port)

	var auth smtp.Auth
	if user != "" {
		auth = smtp.PlainAuth("", user, pass, host)
	}

	// SMTP SendMail (uses TLS handshake if port 465/587 or upgrades via STARTTLS natively if supported)
	// #nosec G707
	err = smtp.SendMail(addr, auth, from, []string{to}, message)
	if err != nil {
		// Log internal SMTP error but return it to be printed
		log.Printf("SMTP failed to send mail: %v", err)
		return err
	}

	return nil
}

func sendDiscord(svc config.ServiceConfig, status string, detail string) error {
	discordURL := os.Getenv("NOTIFICATION_DISCORD_URL")
	if discordURL == "" {
		return fmt.Errorf("NOTIFICATION_DISCORD_URL is not configured in environment")
	}

	color := 16711680 // Red for Down
	emoji := "🚨"
	if status == "Up" {
		color = 65280 // Green for Up
		emoji = "✅"
	}

	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       fmt.Sprintf("%s servworx Alert: %s is %s", emoji, svc.Name, status),
				"description": fmt.Sprintf("Service **%s** (%s) status changed to **%s**.\n\n**Detail:** %s\n**Containers:** `%s`",
					svc.Name, svc.WebsiteURL, status, detail, svc.ContainerNames),
				"color":     color,
				"timestamp": time.Now().Format(time.RFC3339),
			},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// #nosec G107 G704
	req, err := http.NewRequest("POST", discordURL, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	// #nosec G704
	resp, err := defaultHttpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("discord responded with non-2xx status: %d", resp.StatusCode)
	}
	return nil
}

func sendGotify(svc config.ServiceConfig, status string, detail string) error {
	gotifyURL := os.Getenv("NOTIFICATION_GOTIFY_URL")
	token := os.Getenv("NOTIFICATION_GOTIFY_TOKEN")
	if gotifyURL == "" || token == "" {
		return fmt.Errorf("NOTIFICATION_GOTIFY_URL or NOTIFICATION_GOTIFY_TOKEN is not configured in environment")
	}

	gotifyURL = strings.TrimRight(gotifyURL, "/")
	apiURL := fmt.Sprintf("%s/message?token=%s", gotifyURL, token)

	emoji := "🚨"
	priority := 8
	if status == "Up" {
		emoji = "✅"
		priority = 5
	}

	payload := map[string]interface{}{
		"title":    fmt.Sprintf("%s servworx Alert: %s is %s", emoji, svc.Name, status),
		"message":  fmt.Sprintf("Service: %s (%s)\nStatus: %s\n\nDetail: %s\nContainers: %s",
			svc.Name, svc.WebsiteURL, status, detail, svc.ContainerNames),
		"priority": priority,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// #nosec G107 G704
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	// #nosec G704
	resp, err := defaultHttpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("gotify responded with non-2xx status: %d", resp.StatusCode)
	}
	return nil
}

func sendPushover(svc config.ServiceConfig, status string, detail string) error {
	token := os.Getenv("NOTIFICATION_PUSHOVER_TOKEN")
	user := os.Getenv("NOTIFICATION_PUSHOVER_USER")
	if token == "" || user == "" {
		return fmt.Errorf("NOTIFICATION_PUSHOVER_TOKEN or NOTIFICATION_PUSHOVER_USER is not configured in environment")
	}

	emoji := "🚨"
	priority := "1"
	if status == "Up" {
		emoji = "✅"
		priority = "0"
	}

	form := url.Values{}
	form.Set("token", token)
	form.Set("user", user)
	form.Set("title", fmt.Sprintf("%s servworx Alert: %s is %s", emoji, svc.Name, status))
	form.Set("message", fmt.Sprintf("Service: %s (%s) is now %s.\n\nDetail: %s\nContainers: %s",
		svc.Name, svc.WebsiteURL, status, detail, svc.ContainerNames))
	form.Set("priority", priority)

	// #nosec G704
	resp, err := defaultHttpClient.PostForm("https://api.pushover.net/1/messages.json", form)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("pushover responded with non-2xx status: %d", resp.StatusCode)
	}
	return nil
}

// SendTestNotification triggers a single diagnostic test notification over a specific provider.
func SendTestNotification(svc config.ServiceConfig, provider string) error {
	detailMessage := "This is a diagnostic test alert sent from your servworx configuration dashboard. Your notification channel is working correctly!"
	switch provider {
	case "webhook":
		return sendWebhook(svc, "Test", detailMessage)
	case "teams":
		return sendTeams(svc, "Test", detailMessage)
	case "telegram":
		return sendTelegram(svc, "Test", detailMessage)
	case "email":
		return sendEmail(svc, "Test", detailMessage)
	case "discord":
		return sendDiscord(svc, "Test", detailMessage)
	case "gotify":
		return sendGotify(svc, "Test", detailMessage)
	case "pushover":
		return sendPushover(svc, "Test", detailMessage)
	default:
		return fmt.Errorf("unknown notification provider: %s", provider)
	}
}
