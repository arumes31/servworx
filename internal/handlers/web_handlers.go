package handlers

import (
	"fmt"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/arumes31/servworx/internal/auth"
	"github.com/arumes31/servworx/internal/config"
	"github.com/arumes31/servworx/internal/monitor"
)

type ConfigViewData struct {
	Services              []config.ServiceConfig `json:"services"`
	Status                config.Status          `json:"status"`
	Error                 string                 `json:"error,omitempty"`
	Logs                  string                 `json:"logs,omitempty"`
	LogsSvc               string                 `json:"logs_svc,omitempty"`
	NotificationProviders map[string]bool        `json:"notification_providers"`
}

func HandleLoginGET(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth.GetSession(r); ok {
		http.Redirect(w, r, "/config", http.StatusSeeOther)
		return
	}

	isSecure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	_ = templates.ExecuteTemplate(w, "login.html", map[string]interface{}{
		"IsSecure": isSecure,
	})
}

func HandleLoginPOST(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10MB limit
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Request too large", http.StatusRequestEntityTooLarge)
		return
	}

	isSecure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	if !isSecure {
		_ = templates.ExecuteTemplate(w, "login.html", map[string]interface{}{
			"error":    "Login is only possible over a secure (HTTPS) connection.",
			"IsSecure": false,
		})
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	cfg, err := config.LoadConfig()
	if err != nil {
		_ = templates.ExecuteTemplate(w, "login.html", map[string]string{"error": "System error loading config"})
		return
	}

	storedHash, exists := cfg.Users[username]
	if !exists {
		monitor.LogAction(username, "Failed login attempt (invalid credentials)", "error")
		_ = templates.ExecuteTemplate(w, "login.html", map[string]string{"error": "Invalid credentials"})
		return
	}

	if !checkPassword(password, storedHash) {
		monitor.LogAction(username, "Failed login attempt (invalid credentials)", "error")
		_ = templates.ExecuteTemplate(w, "login.html", map[string]string{"error": "Invalid credentials"})
		return
	}

	// Auto-migrate legacy SHA256 hash to bcrypt on successful login
	if !strings.HasPrefix(storedHash, "$2") {
		migratePasswordToBcrypt(username, password)
	}

	// Login successful
	sessionID := auth.CreateSession(username)
	auth.SetSessionCookie(w, sessionID)
	monitor.LogAction(username, "Logged in", "user")

	if username == "admin" {
		if checkPassword("changeme", storedHash) {
			http.Redirect(w, r, "/change_password", http.StatusSeeOther)
			return
		}
	}

	http.Redirect(w, r, "/config", http.StatusSeeOther)
}

func HandleLogout(w http.ResponseWriter, r *http.Request) {
	username, _ := auth.GetSession(r)
	auth.DestroySession(w, r)
	monitor.LogAction(username, "Logged out", "user")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func HandleChangePasswordGET(w http.ResponseWriter, r *http.Request) {
	_ = templates.ExecuteTemplate(w, "change_password.html", nil)
}

func HandleChangePasswordPOST(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10MB limit
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Request too large", http.StatusRequestEntityTooLarge)
		return
	}
	username, _ := auth.GetSession(r)
	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")

	if newPassword != confirmPassword {
		monitor.LogAction(username, "Failed password change (passwords do not match)", "error")
		_ = templates.ExecuteTemplate(w, "change_password.html", map[string]string{"error": "Passwords do not match"})
		return
	}

	if len(newPassword) < 8 {
		monitor.LogAction(username, "Failed password change (weak password)", "error")
		_ = templates.ExecuteTemplate(w, "change_password.html", map[string]string{"error": "Password must be at least 8 characters long"})
		return
	}

	hashed, err := hashPassword(newPassword)
	if err != nil {
		monitor.LogAction(username, "Failed password change (hashing error)", "error")
		_ = templates.ExecuteTemplate(w, "change_password.html", map[string]string{"error": "System error processing password"})
		return
	}

	err = config.UpdateConfig(func(cfg *config.Config) {
		cfg.Users[username] = hashed
	})

	if err != nil {
		_ = templates.ExecuteTemplate(w, "change_password.html", map[string]string{"error": "Failed to save new password"})
		return
	}

	monitor.LogAction(username, "Changed password", "user")
	http.Redirect(w, r, "/config", http.StatusSeeOther)
}

func HandleConfigGET(w http.ResponseWriter, r *http.Request) {
	username, _ := auth.GetSession(r)
	monitor.LogAction(username, "Accessed configuration page", "user")

	cfg, errCfg := config.LoadConfig()
	status, errStatus := config.LoadStatus()

	if errCfg != nil || errStatus != nil || cfg == nil || status == nil {
		http.Error(w, "System error loading config", http.StatusInternalServerError)
		return
	}

	currentTime := time.Now().Unix()
	for i := range cfg.Services {
		if i < len(status.Services) {
			_ = enrichServiceStatus(cfg.Services[i], &status.Services[i], currentTime)
		}
	}

	data := ConfigViewData{
		Services:              cfg.Services,
		Status:                *status,
		NotificationProviders: getNotificationProviders(),
	}

	_ = templates.ExecuteTemplate(w, "config.html", data)
}

func handleDeleteService(w http.ResponseWriter, r *http.Request, username string, idx int, cfg *config.Config) {
	deletedName := cfg.Services[idx].Name
	_ = config.UpdateConfig(func(c *config.Config) {
		c.Services = append(c.Services[:idx], c.Services[idx+1:]...)
	})
	_ = config.UpdateStatus(func(s *config.Status) {
		for i, sts := range s.Services {
			if sts.Name == deletedName {
				s.Services = append(s.Services[:i], s.Services[i+1:]...)
				break
			}
		}
	})
	monitor.LogAction(username, fmt.Sprintf("Deleted service: %s", deletedName), "user")
	monitor.LogAction("System", fmt.Sprintf("Removed status for service: %s", deletedName), "system")

	monitor.RestartMonitoring()
	http.Redirect(w, r, "/config", http.StatusSeeOther)
}

func handleUpdateService(w http.ResponseWriter, r *http.Request, username string, idx int, cfg *config.Config) {
	retries, err1 := strconv.Atoi(r.FormValue("retries"))
	interval, err2 := strconv.Atoi(r.FormValue("interval"))
	gracePeriod, err3 := strconv.Atoi(r.FormValue("grace_period"))

	if err1 != nil || err2 != nil || err3 != nil || retries < 1 || interval < 1 || gracePeriod < 1 {
		monitor.LogAction(username, "Invalid numeric inputs for service", "error")
		renderConfigWithError(w, "Retries, interval, and grace period must be positive integers")
		return
	}

	codes, err := parseStatusCodes(r.FormValue("accepted_status_codes"))
	if err != nil {
		renderConfigWithError(w, "Invalid status codes")
		return
	}

	containerNames := r.FormValue("container_names")
	for _, c := range strings.Split(containerNames, ",") {
		c = strings.TrimSpace(c)
		if c != "" && !config.IsValidContainerName(c) {
			monitor.LogAction(username, fmt.Sprintf("Invalid container name provided: %s", c), "error")
			renderConfigWithError(w, fmt.Sprintf("Invalid container name: %s", c))
			return
		}
	}

	oldName := cfg.Services[idx].Name
	newName := r.FormValue("name")
	insecureSkip := r.FormValue("insecure_skip_verify") == "on"

	providers := getNotificationProviders()
	enableWebhook := r.FormValue("enable_webhook") == "on" && providers["webhook"]
	enableTeams := r.FormValue("enable_teams") == "on" && providers["teams"]
	enableTelegram := r.FormValue("enable_telegram") == "on" && providers["telegram"]
	enableEmail := r.FormValue("enable_email") == "on" && providers["email"]
	enableDiscord := r.FormValue("enable_discord") == "on" && providers["discord"]
	enableGotify := r.FormValue("enable_gotify") == "on" && providers["gotify"]
	enablePushover := r.FormValue("enable_pushover") == "on" && providers["pushover"]

	alertOnFailure := r.FormValue("alert_on_failure") == "on"
	alertOnRecovery := r.FormValue("alert_on_recovery") == "on"
	alertOnRestart := r.FormValue("alert_on_restart") == "on"

	quietHoursStart := r.FormValue("quiet_hours_start")
	quietHoursEnd := r.FormValue("quiet_hours_end")

	repeatIntervalMin, _ := strconv.Atoi(r.FormValue("alert_repeat_interval"))
	alertRepeatInterval := repeatIntervalMin * 60
	if alertRepeatInterval < 0 {
		alertRepeatInterval = 0
	}

	alertMaxRepeats, _ := strconv.Atoi(r.FormValue("alert_max_repeats"))
	if alertMaxRepeats < 0 {
		alertMaxRepeats = 0
	}

	_ = config.UpdateConfig(func(c *config.Config) {
		c.Services[idx].Name = newName
		c.Services[idx].WebsiteURL = r.FormValue("website_url")
		c.Services[idx].ContainerNames = containerNames
		c.Services[idx].Retries = retries
		c.Services[idx].Interval = interval
		c.Services[idx].GracePeriod = gracePeriod
		c.Services[idx].AcceptedStatusCodes = codes
		c.Services[idx].InsecureSkipVerify = insecureSkip
		c.Services[idx].EnableWebhook = enableWebhook
		c.Services[idx].EnableTeams = enableTeams
		c.Services[idx].EnableTelegram = enableTelegram
		c.Services[idx].EnableEmail = enableEmail
		c.Services[idx].EnableDiscord = enableDiscord
		c.Services[idx].EnableGotify = enableGotify
		c.Services[idx].EnablePushover = enablePushover
		c.Services[idx].QuietHoursStart = quietHoursStart
		c.Services[idx].QuietHoursEnd = quietHoursEnd
		c.Services[idx].AlertOnFailure = alertOnFailure
		c.Services[idx].AlertOnRecovery = alertOnRecovery
		c.Services[idx].AlertOnRestart = alertOnRestart
		c.Services[idx].AlertRepeatInterval = alertRepeatInterval
		c.Services[idx].AlertMaxRepeats = alertMaxRepeats
	})

	if oldName != newName {
		_ = config.UpdateStatus(func(s *config.Status) {
			for i := range s.Services {
				if s.Services[i].Name == oldName {
					s.Services[i].Name = newName
					monitor.LogAction("System", fmt.Sprintf("Updated status name from %s to %s", oldName, newName), "system")
					break
				}
			}
		})
	}

	monitor.LogAction(username, fmt.Sprintf("Updated service %d successfully", idx), "user")
	monitor.RestartMonitoring()
	http.Redirect(w, r, "/config", http.StatusSeeOther)
}

func HandleUpdateServicePOST(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10MB limit
	_ = r.ParseForm()
	username, _ := auth.GetSession(r)
	idx, ok := parseIndex(w, r)
	if !ok {
		return
	}

	action := r.FormValue("form_action")
	monitor.LogAction(username, fmt.Sprintf("Reached update_service endpoint for index %d with action %s", idx, action), "user")

	cfg, err := config.LoadConfig()
	if err != nil {
		monitor.LogAction(username, fmt.Sprintf("System error loading config: %v", err), "error")
		renderConfigWithError(w, "System error loading config")
		return
	}
	if idx < 0 || idx >= len(cfg.Services) {
		monitor.LogAction(username, fmt.Sprintf("Invalid service index %d", idx), "error")
		renderConfigWithError(w, fmt.Sprintf("Invalid service index: %d", idx))
		return
	}

	if action == "delete" {
		handleDeleteService(w, r, username, idx, cfg)
		return
	}

	if action == "update" {
		handleUpdateService(w, r, username, idx, cfg)
		return
	}
}

func HandleForceRestartPOST(w http.ResponseWriter, r *http.Request) {
	username, _ := auth.GetSession(r)
	idx, ok := parseIndex(w, r)
	if !ok {
		return
	}

	monitor.LogAction(username, fmt.Sprintf("Requested force restart for service index %d", idx), "user")
	cfg, err := config.LoadConfig()
	if err != nil {
		renderConfigWithError(w, "System error loading config")
		return
	}
	if idx < 0 || idx >= len(cfg.Services) {
		renderConfigWithError(w, fmt.Sprintf("Invalid service index: %d", idx))
		return
	}

	svc := cfg.Services[idx]

	go func(names, name string, user string) {
		containers := strings.Split(names, ",")
		restartSucceeded := true
		for _, c := range containers {
			c = strings.TrimSpace(c)
			if c == "" {
				continue
			}
			if !config.IsValidContainerName(c) {
				monitor.LogAction(user, fmt.Sprintf("Invalid container name blocked from restart: %s", c), "error")
				restartSucceeded = false
				continue
			}
			// #nosec G204
			cmd := exec.Command("docker", "restart", c)
			if err := cmd.Run(); err != nil {
				monitor.LogAction(user, fmt.Sprintf("Error restarting container %s: %v", c, err), "error")
				restartSucceeded = false
			}
		}

		if restartSucceeded {
			nowStr := time.Now().Format("2006-01-02 15:04:05")
			_ = config.UpdateStatus(func(s *config.Status) {
				for i := range s.Services {
					if s.Services[i].Name == name {
						s.Services[i].LastFailure = &nowStr
					}
				}
			})
			monitor.LogAction(user, fmt.Sprintf("Forced restart for service: %s", name), "user")
		}
	}(svc.ContainerNames, svc.Name, username)

	http.Redirect(w, r, "/config", http.StatusSeeOther)
}

func HandlePauseMonitoringPOST(w http.ResponseWriter, r *http.Request) {
	username, _ := auth.GetSession(r)
	idx, ok := parseIndex(w, r)
	if !ok {
		return
	}

	monitor.LogAction(username, fmt.Sprintf("Requested pause/resume monitoring for service index %d", idx), "user")
	cfg, err := config.LoadConfig()
	if err != nil {
		renderConfigWithError(w, "System error loading config")
		return
	}
	if idx < 0 || idx >= len(cfg.Services) {
		renderConfigWithError(w, fmt.Sprintf("Invalid service index: %d", idx))
		return
	}

	var paused bool
	var name string
	_ = config.UpdateConfig(func(c *config.Config) {
		c.Services[idx].Paused = !c.Services[idx].Paused
		paused = c.Services[idx].Paused
		name = c.Services[idx].Name
	})

	action := "resumed"
	if paused {
		action = "paused"
	}
	monitor.LogAction(username, fmt.Sprintf("Monitoring %s for service: %s", action, name), "user")

	monitor.RestartMonitoring()
	http.Redirect(w, r, "/config", http.StatusSeeOther)
}

func HandleViewLogsGET(w http.ResponseWriter, r *http.Request) {
	username, _ := auth.GetSession(r)
	idx, ok := parseIndex(w, r)
	if !ok {
		return
	}

	monitor.LogAction(username, fmt.Sprintf("Requested logs for service index %d", idx), "user")
	cfg, err := config.LoadConfig()
	if err != nil {
		renderConfigWithError(w, "System error loading config")
		return
	}
	if idx < 0 || idx >= len(cfg.Services) {
		renderConfigWithError(w, fmt.Sprintf("Invalid service index: %d", idx))
		return
	}

	svc := cfg.Services[idx]
	containers := strings.Split(svc.ContainerNames, ",")
	var logsBuilder strings.Builder

	for _, c := range containers {
		c = strings.TrimSpace(c)
		if c != "" {
			if !config.IsValidContainerName(c) {
				monitor.LogAction(username, fmt.Sprintf("Invalid container name blocked from logs: %s", c), "error")
				fmt.Fprintf(&logsBuilder, "Logs for %s: [Invalid container name]\n\n", c)
				continue
			}
			// #nosec G204
			cmd := exec.Command("docker", "logs", "--tail", "10", c)
			out, _ := cmd.CombinedOutput()
			outStr := string(out)
			if outStr == "" {
				outStr = "No logs available"
			}
			fmt.Fprintf(&logsBuilder, "Logs for %s:\n%s\n\n", c, outStr)
		}
	}

	monitor.LogAction(username, fmt.Sprintf("Retrieved logs for service: %s", svc.Name), "user")

	cfg, _ = config.LoadConfig()
	status, _ := config.LoadStatus()
	if cfg == nil || status == nil {
		http.Error(w, "System error loading config", http.StatusInternalServerError)
		return
	}

	currentTime := time.Now().Unix()
	for i := range cfg.Services {
		if i < len(status.Services) {
			_ = enrichServiceStatus(cfg.Services[i], &status.Services[i], currentTime)
		}
	}

	_ = templates.ExecuteTemplate(w, "config.html", ConfigViewData{
		Services:              cfg.Services,
		Status:                *status,
		Logs:                  logsBuilder.String(),
		LogsSvc:               svc.Name,
		NotificationProviders: getNotificationProviders(),
	})
}

func HandleAddServicePOST(w http.ResponseWriter, r *http.Request) {
	username, _ := auth.GetSession(r)
	monitor.LogAction(username, "Received add service request", "user")

	var newName string
	_ = config.UpdateConfig(func(c *config.Config) {
		newName = fmt.Sprintf("Service%d", len(c.Services)+1)
		c.Services = append(c.Services, config.ServiceConfig{
			Name:                newName,
			WebsiteURL:          "http://example.com",
			ContainerNames:      "",
			Retries:             15,
			Interval:            120,
			GracePeriod:         3600,
			AcceptedStatusCodes: []int{200},
			Paused:              false,
			InsecureSkipVerify:  false,
			EnableWebhook:       false,
			EnableTeams:         false,
			EnableTelegram:      false,
			EnableEmail:         false,
			AlertOnFailure:      true,
			AlertOnRecovery:     true,
			AlertOnRestart:      true,
			AlertRepeatInterval: 0,
			AlertMaxRepeats:     0,
		})
	})

	_ = config.UpdateStatus(func(s *config.Status) {
		s.Services = append(s.Services, config.ServiceStatus{
			Name:             newName,
			Status:           "Unknown",
			LastStableStatus: "Unknown",
		})
	})

	monitor.LogAction(username, fmt.Sprintf("Added new service: %s", newName), "user")
	monitor.LogAction("System", fmt.Sprintf("Initialized status for new service: %s", newName), "system")

	monitor.RestartMonitoring()

	if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"success": true, "message": "Service added successfully"}`)
		return
	}

	http.Redirect(w, r, "/config", http.StatusSeeOther)
}
