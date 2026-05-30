package monitor

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/arumes31/servworx/internal/config"
)

func TestSendWebhook(t *testing.T) {
	// Create mock HTTP server
	var receivedPayload WebhookPayload
	var contentType string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Configure Env
	os.Setenv("NOTIFICATION_WEBHOOK_URL", ts.URL)
	defer os.Unsetenv("NOTIFICATION_WEBHOOK_URL")

	svc := config.ServiceConfig{
		Name:           "TestService",
		WebsiteURL:     "http://example.com",
		ContainerNames: "nginx,mysql",
	}

	err := sendWebhook(svc, "Down", "Integrity checks failed.")
	if err != nil {
		t.Fatalf("sendWebhook failed: %v", err)
	}

	if contentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", contentType)
	}
	if receivedPayload.Service != "TestService" {
		t.Errorf("expected Service TestService, got %s", receivedPayload.Service)
	}
	if receivedPayload.Status != "Down" {
		t.Errorf("expected Status Down, got %s", receivedPayload.Status)
	}
	if receivedPayload.Message != "Integrity checks failed." {
		t.Errorf("expected Message 'Integrity checks failed.', got %s", receivedPayload.Message)
	}
}

func TestSendTeams(t *testing.T) {
	var receivedPayload map[string]interface{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	os.Setenv("NOTIFICATION_MSTEAMS_URL", ts.URL)
	defer os.Unsetenv("NOTIFICATION_MSTEAMS_URL")

	svc := config.ServiceConfig{
		Name:           "TeamsService",
		WebsiteURL:     "http://example.com",
		ContainerNames: "web",
	}

	err := sendTeams(svc, "Up", "Service recovered.")
	if err != nil {
		t.Fatalf("sendTeams failed: %v", err)
	}

	if receivedPayload["@type"] != "MessageCard" {
		t.Errorf("expected type MessageCard, got %v", receivedPayload["@type"])
	}
	if !strings.Contains(receivedPayload["text"].(string), "TeamsService") {
		t.Errorf("expected payload text to contain TeamsService, got %v", receivedPayload["text"])
	}
}

func TestSendTelegram(t *testing.T) {
	var receivedPayload map[string]interface{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	os.Setenv("NOTIFICATION_TELEGRAM_TOKEN", "mock-token-12345")
	os.Setenv("NOTIFICATION_TELEGRAM_CHAT_ID", "mock-chat-12345")
	os.Setenv("NOTIFICATION_TELEGRAM_BASE_URL", ts.URL)
	defer os.Unsetenv("NOTIFICATION_TELEGRAM_TOKEN")
	defer os.Unsetenv("NOTIFICATION_TELEGRAM_CHAT_ID")
	defer os.Unsetenv("NOTIFICATION_TELEGRAM_BASE_URL")

	svc := config.ServiceConfig{
		Name:           "TelegramService",
		WebsiteURL:     "http://example.com",
		ContainerNames: "web",
	}

	err := sendTelegram(svc, "Down", "Health check failed.")
	if err != nil {
		t.Fatalf("sendTelegram failed: %v", err)
	}

	if receivedPayload["chat_id"] != "mock-chat-12345" {
		t.Errorf("expected chat_id mock-chat-12345, got %v", receivedPayload["chat_id"])
	}
	if !strings.Contains(receivedPayload["text"].(string), "TelegramService") {
		t.Errorf("expected payload text to contain TelegramService, got %v", receivedPayload["text"])
	}
}

func TestSendTelegramMissingConfig(t *testing.T) {
	os.Unsetenv("NOTIFICATION_TELEGRAM_TOKEN")
	os.Unsetenv("NOTIFICATION_TELEGRAM_CHAT_ID")

	svc := config.ServiceConfig{Name: "Svc"}
	err := sendTelegram(svc, "Down", "Err")
	if err == nil {
		t.Error("expected error due to missing Telegram environment variables")
	}
}

func TestSendEmailMockSMTP(t *testing.T) {
	// Start mock TCP SMTP Server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock SMTP server: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()
	parts := strings.Split(addr, ":")
	host := parts[0]
	port := parts[1]

	var receivedEmail strings.Builder
	serverErrChan := make(chan error, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErrChan <- err
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		writer := bufio.NewWriter(conn)

		// 1. Greet Client
		_, _ = writer.WriteString("220 mock.smtp.com\r\n")
		writer.Flush()

		// 2. Read EHLO
		line, _ := reader.ReadString('\n')
		if !strings.HasPrefix(line, "EHLO") && !strings.HasPrefix(line, "HELO") {
			serverErrChan <- fmt.Errorf("expected EHLO/HELO, got: %s", line)
			return
		}
		_, _ = writer.WriteString("250-mock.smtp.com\r\n250 8BITMIME\r\n")
		writer.Flush()

		// 3. Read MAIL FROM
		line, _ = reader.ReadString('\n')
		if !strings.HasPrefix(line, "MAIL FROM") {
			serverErrChan <- fmt.Errorf("expected MAIL FROM, got: %s", line)
			return
		}
		_, _ = writer.WriteString("250 2.1.0 Ok\r\n")
		writer.Flush()

		// 4. Read RCPT TO
		line, _ = reader.ReadString('\n')
		if !strings.HasPrefix(line, "RCPT TO") {
			serverErrChan <- fmt.Errorf("expected RCPT TO, got: %s", line)
			return
		}
		_, _ = writer.WriteString("250 2.1.5 Ok\r\n")
		writer.Flush()

		// 5. Read DATA
		line, _ = reader.ReadString('\n')
		if !strings.HasPrefix(line, "DATA") {
			serverErrChan <- fmt.Errorf("expected DATA, got: %s", line)
			return
		}
		_, _ = writer.WriteString("354 Start mail input; end with <CRLF>.<CRLF>\r\n")
		writer.Flush()

		// 6. Read Message content until .\r\n
		for {
			line, err = reader.ReadString('\n')
			if err != nil {
				break
			}
			if line == ".\r\n" {
				break
			}
			receivedEmail.WriteString(line)
		}
		_, _ = writer.WriteString("250 2.0.0 Ok: queued as 12345\r\n")
		writer.Flush()

		// 7. Read QUIT
		_, _ = reader.ReadString('\n')
		_, _ = writer.WriteString("221 2.0.0 Bye\r\n")
		writer.Flush()

		serverErrChan <- nil
	}()

	// Configure Env
	os.Setenv("NOTIFICATION_SMTP_HOST", host)
	os.Setenv("NOTIFICATION_SMTP_PORT", port)
	os.Setenv("NOTIFICATION_SMTP_USER", "") // Unauthenticated SMTP mock
	os.Setenv("NOTIFICATION_SMTP_PASS", "")
	os.Setenv("NOTIFICATION_SMTP_FROM", "sender@example.com")
	os.Setenv("NOTIFICATION_SMTP_TO", "receiver@example.com")

	defer func() {
		os.Unsetenv("NOTIFICATION_SMTP_HOST")
		os.Unsetenv("NOTIFICATION_SMTP_PORT")
		os.Unsetenv("NOTIFICATION_SMTP_USER")
		os.Unsetenv("NOTIFICATION_SMTP_PASS")
		os.Unsetenv("NOTIFICATION_SMTP_FROM")
		os.Unsetenv("NOTIFICATION_SMTP_TO")
	}()

	svc := config.ServiceConfig{
		Name:           "SMTPService",
		WebsiteURL:     "http://example.com",
		ContainerNames: "nginx",
	}

	err = sendEmail(svc, "Down", "Integrity checks failed.")
	if err != nil {
		t.Fatalf("sendEmail failed: %v", err)
	}

	select {
	case serr := <-serverErrChan:
		if serr != nil {
			t.Fatalf("mock SMTP server error: %v", serr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for mock SMTP server transaction")
	}

	emailContent := receivedEmail.String()
	if !strings.Contains(emailContent, "SMTPService") {
		t.Errorf("expected email content to contain SMTPService, got: %s", emailContent)
	}
	if !strings.Contains(emailContent, "Subject:") {
		t.Errorf("expected email content to contain Subject, got: %s", emailContent)
	}
}
