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

// SendNotification dispatches asynchronous alerts over enabled channels on status transitions
func SendNotification(svc config.ServiceConfig, status string, detailMessage string) {
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

	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(data)) // #nosec G107
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

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

	req, err := http.NewRequest("POST", teamsURL, bytes.NewBuffer(data)) // #nosec G107
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

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
	req, err := http.NewRequest("POST", telegramURL, bytes.NewBuffer(data)) // #nosec G107
	if err != nil {
		return fmt.Errorf("telegram request creation failed")
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := defaultHttpClient.Do(req)
	if err != nil {
		// Sanitize error to prevent leaking the bot token from *url.Error
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			return fmt.Errorf("telegram request failed: %s", urlErr.Err.Error())
		}
		return fmt.Errorf("telegram request failed")
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
	err = smtp.SendMail(addr, auth, from, []string{to}, message)
	if err != nil {
		// Log internal SMTP error but return it to be printed
		log.Printf("SMTP failed to send mail: %v", err)
		return err
	}

	return nil
}
