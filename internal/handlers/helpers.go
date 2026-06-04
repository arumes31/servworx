package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/arumes31/servworx/internal/config"
	"github.com/arumes31/servworx/internal/monitor"
)

var templates *template.Template

func InitTemplates(templateDir string) {
	templates = template.Must(template.New("").Funcs(template.FuncMap{
		"div": func(a, b int) int {
			if b == 0 {
				return 0
			}
			return a / b
		},
	}).ParseGlob(filepath.Join(templateDir, "*.html")))
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPassword(password, storedHash string) bool {
	if strings.HasPrefix(storedHash, "$2") {
		return bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password)) == nil
	}
	if len(storedHash) == 64 {
		sum := sha256.Sum256([]byte(password))
		return hex.EncodeToString(sum[:]) == storedHash
	}
	return false
}

func migratePasswordToBcrypt(username, password string) {
	newHash, err := hashPassword(password)
	if err != nil {
		monitor.LogAction("System", fmt.Sprintf("Failed to migrate password for %s: %v", username, err), "error")
		return
	}
	_ = config.UpdateConfig(func(cfg *config.Config) {
		cfg.Users[username] = newHash
	})
	monitor.LogAction("System", fmt.Sprintf("Migrated password hash to bcrypt for user: %s", username), "system")
}

func formatDuration(seconds int64) string {
	if seconds <= 0 {
		return "0 seconds"
	}
	days := seconds / (24 * 3600)
	seconds %= (24 * 3600)
	hours := seconds / 3600
	seconds %= 3600
	minutes := seconds / 60
	seconds %= 60

	var parts []string
	if days > 0 {
		s := ""
		if days != 1 {
			s = "s"
		}
		parts = append(parts, fmt.Sprintf("%d day%s", days, s))
	}
	if hours > 0 {
		s := ""
		if hours != 1 {
			s = "s"
		}
		parts = append(parts, fmt.Sprintf("%d hour%s", hours, s))
	}
	if minutes > 0 {
		s := ""
		if minutes != 1 {
			s = "s"
		}
		parts = append(parts, fmt.Sprintf("%d minute%s", minutes, s))
	}
	if seconds > 0 || len(parts) == 0 {
		s := ""
		if seconds != 1 {
			s = "s"
		}
		parts = append(parts, fmt.Sprintf("%d second%s", seconds, s))
	}
	return strings.Join(parts, ", ")
}

func getNotificationProviders() map[string]bool {
	return map[string]bool{
		"webhook":  os.Getenv("NOTIFICATION_WEBHOOK_URL") != "",
		"teams":    os.Getenv("NOTIFICATION_MSTEAMS_URL") != "",
		"telegram": os.Getenv("NOTIFICATION_TELEGRAM_TOKEN") != "" && os.Getenv("NOTIFICATION_TELEGRAM_CHAT_ID") != "",
		"email":    os.Getenv("NOTIFICATION_SMTP_HOST") != "" && os.Getenv("NOTIFICATION_SMTP_PORT") != "" && os.Getenv("NOTIFICATION_SMTP_FROM") != "" && os.Getenv("NOTIFICATION_SMTP_TO") != "",
		"discord":  os.Getenv("NOTIFICATION_DISCORD_URL") != "",
		"gotify":   os.Getenv("NOTIFICATION_GOTIFY_URL") != "" && os.Getenv("NOTIFICATION_GOTIFY_TOKEN") != "",
		"pushover": os.Getenv("NOTIFICATION_PUSHOVER_TOKEN") != "" && os.Getenv("NOTIFICATION_PUSHOVER_USER") != "",
	}
}

func renderConfigWithError(w http.ResponseWriter, errMsg string) {
	cfg, _ := config.LoadConfig()
	status, _ := config.LoadStatus()
	currentTime := time.Now().Unix()
	for i := range cfg.Services {
		if i < len(status.Services) {
			_ = enrichServiceStatus(cfg.Services[i], &status.Services[i], currentTime)
		}
	}
	_ = templates.ExecuteTemplate(w, "config.html", ConfigViewData{
		Services:              cfg.Services,
		Status:                *status,
		Error:                 errMsg,
		NotificationProviders: getNotificationProviders(),
	})
}

func parseIndex(w http.ResponseWriter, r *http.Request) (int, bool) {
	idxStr := r.PathValue("index")
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		renderConfigWithError(w, "Invalid service index format")
		return 0, false
	}
	return idx, true
}

func parseStatusCodes(codesStr string) ([]int, error) {
	var codes []int
	if strings.TrimSpace(codesStr) == "" {
		return []int{200}, nil
	}
	parts := strings.Split(codesStr, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			c, err := strconv.Atoi(p)
			if err != nil {
				return nil, err
			}
			codes = append(codes, c)
		}
	}
	if len(codes) == 0 {
		return []int{200}, nil
	}
	return codes, nil
}

func enrichServiceStatus(svc config.ServiceConfig, s *config.ServiceStatus, currentTime int64) []string {
	s.TimeToRestart = formatDuration(int64(svc.Interval * svc.Retries))
	if s.DownSince != nil {
		t, err := time.ParseInLocation("2006-01-02 15:04:05", *s.DownSince, time.Local)
		if err == nil {
			df := formatDuration(currentTime - t.Unix())
			s.DownFor = &df
		} else {
			errStr := "Invalid timestamp"
			s.DownFor = &errStr
		}
	}
	if s.UpSince != nil {
		t, err := time.ParseInLocation("2006-01-02 15:04:05", *s.UpSince, time.Local)
		if err == nil {
			uf := formatDuration(currentTime - t.Unix())
			s.UpFor = &uf
		} else {
			errStr := "Invalid timestamp"
			s.UpFor = &errStr
		}
	}
	return monitor.GetHistory(svc.Name)
}
