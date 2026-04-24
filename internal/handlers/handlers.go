package handlers

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/arumes31/servworx/internal/auth"
	"github.com/arumes31/servworx/internal/config"
	"github.com/arumes31/servworx/internal/monitor"
)

var templates *template.Template

func InitTemplates(templateDir string) {
	templates = template.Must(template.ParseGlob(filepath.Join(templateDir, "*.html")))
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// checkPassword verifies a password against a stored hash.
// It supports bcrypt (Go) format.
// Returns true if the password matches.
func checkPassword(password, storedHash string) bool {
	// Bcrypt hashes always start with "$2a$", "$2b$", or "$2y$"
	if strings.HasPrefix(storedHash, "$2") {
		return bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password)) == nil
	}

	return false
}

// formatDuration matches Python's format_duration output closely
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
	appendPart := func(value int64, unit string) {
		if value > 0 {
			s := ""
			if value != 1 {
				s = "s"
			}
			parts = append(parts, fmt.Sprintf("%d %s%s", value, unit, s))
		}
	}

	appendPart(days, "day")
	appendPart(hours, "hour")
	appendPart(minutes, "minute")

	if seconds > 0 || len(parts) == 0 {
		s := ""
		if seconds != 1 {
			s = "s"
		}
		parts = append(parts, fmt.Sprintf("%d second%s", seconds, s))
	}
	return strings.Join(parts, ", ")
}

// enrichServiceStatus populates duration strings and history for a service status
func enrichServiceStatus(s *config.ServiceStatus, svc config.ServiceConfig, currentTime int64) APIServiceStatus {
	s.TimeToRestart = formatDuration(int64(svc.Interval * svc.Retries))

	if s.DownSince != nil {
		t, err := time.Parse("2006-01-02 15:04:05", *s.DownSince)
		if err == nil {
			df := formatDuration(currentTime - t.Unix())
			s.DownFor = &df
		} else {
			errStr := "Invalid timestamp"
			s.DownFor = &errStr
		}
	}
	if s.UpSince != nil {
		t, err := time.Parse("2006-01-02 15:04:05", *s.UpSince)
		if err == nil {
			uf := formatDuration(currentTime - t.Unix())
			s.UpFor = &uf
		} else {
			errStr := "Invalid timestamp"
			s.UpFor = &errStr
		}
	}

	return APIServiceStatus{
		ServiceStatus: *s,
		History:       monitor.GetHistory(svc.Name),
	}
}

// requireAuth is a middleware to enforce authentication
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, ok := auth.GetSession(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Ensure admin has changed default password
		if username == "admin" && r.URL.Path != "/change_password" && r.URL.Path != "/logout" {
			cfg, err := config.LoadConfig()
			if err == nil {
				if checkPassword("changeme", cfg.Users["admin"]) {
					http.Redirect(w, r, "/change_password", http.StatusSeeOther)
					return
				}
			}
		}

		// Store user in context or just let handlers get it from session wrapper if needed
		next(w, r)
	}
}

func RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if _, ok := auth.GetSession(r); !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/config", http.StatusSeeOther)
	})

	mux.HandleFunc("GET /login", HandleLoginGET)
	mux.HandleFunc("POST /login", HandleLoginPOST)
	mux.HandleFunc("GET /logout", requireAuth(HandleLogout))
	mux.HandleFunc("GET /change_password", requireAuth(HandleChangePasswordGET))
	mux.HandleFunc("POST /change_password", requireAuth(HandleChangePasswordPOST))
	mux.HandleFunc("GET /config", requireAuth(HandleConfigGET))
	mux.HandleFunc("POST /update_service/{index}", requireAuth(HandleUpdateServicePOST))
	mux.HandleFunc("POST /add_service", requireAuth(HandleAddServicePOST))
	mux.HandleFunc("POST /force_restart/{index}", requireAuth(HandleForceRestartPOST))
	mux.HandleFunc("POST /pause_monitoring/{index}", requireAuth(HandlePauseMonitoringPOST))
	mux.HandleFunc("GET /view_logs/{index}", requireAuth(HandleViewLogsGET))

	// JSON / AJAX UX Endpoints
	mux.HandleFunc("GET /api/status", requireAuth(HandleAPIStatusGET))
	mux.HandleFunc("GET /api/logs/stream/{index}", requireAuth(HandleAPILogsStreamGET))
}

func HandleLoginGET(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth.GetSession(r); ok {
		http.Redirect(w, r, "/config", http.StatusSeeOther)
		return
	}
	_ = templates.ExecuteTemplate(w, "login.html", nil)
}

func HandleLoginPOST(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10MB limit
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Request too large", http.StatusRequestEntityTooLarge)
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

type ConfigViewData struct {
	Services []config.ServiceConfig `json:"services"`
	Status   config.Status          `json:"status"`
	Error    string                 `json:"error,omitempty"`
	Logs     string                 `json:"logs,omitempty"`
	LogsSvc  string                 `json:"logs_svc,omitempty"`
}

// APIServiceStatus extends config.ServiceStatus with history for API responses
type APIServiceStatus struct {
	config.ServiceStatus
	History []string `json:"history"`
}

// APIStatusResponse represents the structured status response for the API
type APIStatusResponse struct {
	Services []APIServiceStatus `json:"services"`
}

// APIViewData is the top-level structure for the API status response
type APIViewData struct {
	Services []config.ServiceConfig `json:"services"`
	Status   APIStatusResponse      `json:"status"`
}

func HandleConfigGET(w http.ResponseWriter, r *http.Request) {
	username, _ := auth.GetSession(r)
	monitor.LogAction(username, "Accessed configuration page", "user")

	cfg, _ := config.LoadConfig()
	status, _ := config.LoadStatus()

	// Recalculate UI fields
	currentTime := time.Now().Unix()

	for i, svc := range cfg.Services {
		if i < len(status.Services) {
			_ = enrichServiceStatus(&status.Services[i], svc, currentTime)
		}
	}

	// Just display
	data := ConfigViewData{
		Services: cfg.Services,
		Status:   *status,
	}

	// Extract potential error/logs parameters passed explicitly by other methods to this view.
	// Since we are rebuilding, we don't have flash sessions, so we rely on explicit data injection
	// from methods rendering directly or via query params (we render directly on error).

	_ = templates.ExecuteTemplate(w, "config.html", data)
}

// renderConfigWithError is a helper for returning the config page with an error immediately
func renderConfigWithError(w http.ResponseWriter, errMsg string) {
	cfg, _ := config.LoadConfig()
	status, _ := config.LoadStatus()
	_ = templates.ExecuteTemplate(w, "config.html", ConfigViewData{
		Services: cfg.Services,
		Status:   *status,
		Error:    errMsg,
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

func HandleUpdateServicePOST(w http.ResponseWriter, r *http.Request) {
	username, _ := auth.GetSession(r)
	idx, ok := parseIndex(w, r)
	if !ok {
		return
	}

	action := r.FormValue("form_action")
	monitor.LogAction(username, fmt.Sprintf("Reached update_service endpoint for index %d with action %s", idx, action), "user")

	cfg, _ := config.LoadConfig()
	if idx < 0 || idx >= len(cfg.Services) {
		monitor.LogAction(username, fmt.Sprintf("Invalid service index %d", idx), "error")
		renderConfigWithError(w, fmt.Sprintf("Invalid service index: %d", idx))
		return
	}

	if action == "delete" {
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
		return
	}

	if action == "update" {
		r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10MB limit
		_ = r.ParseForm()
		retries, err1 := strconv.Atoi(r.FormValue("retries"))
		interval, err2 := strconv.Atoi(r.FormValue("interval"))
		gracePeriod, err3 := strconv.Atoi(r.FormValue("grace_period"))

		if err1 != nil || err2 != nil || err3 != nil || retries < 1 || interval < 1 || gracePeriod < 1 {
			monitor.LogAction(username, "Invalid numeric inputs for service", "error")
			renderConfigWithError(w, "Retries, interval, and grace period must be positive integers")
			return
		}

		codesStr := r.FormValue("accepted_status_codes")
		var codes []int
		if strings.TrimSpace(codesStr) == "" {
			codes = []int{200}
			monitor.LogAction(username, fmt.Sprintf("Service %d: Empty accepted_status_codes, defaulting to [200]", idx), "user")
		} else {
			parts := strings.Split(codesStr, ",")
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p != "" {
					c, err := strconv.Atoi(p)
					if err != nil {
						renderConfigWithError(w, "Invalid status codes")
						return
					}
					codes = append(codes, c)
				}
			}
			if len(codes) == 0 {
				codes = []int{200}
				monitor.LogAction(username, fmt.Sprintf("Service %d: No valid accepted_status_codes, defaulting to [200]", idx), "user")
			}
		}

		oldName := cfg.Services[idx].Name
		newName := r.FormValue("name")
		insecureSkip := r.FormValue("insecure_skip_verify") == "on"

		_ = config.UpdateConfig(func(c *config.Config) {
			c.Services[idx].Name = newName
			c.Services[idx].WebsiteURL = r.FormValue("website_url")
			c.Services[idx].ContainerNames = r.FormValue("container_names")
			c.Services[idx].Retries = retries
			c.Services[idx].Interval = interval
			c.Services[idx].GracePeriod = gracePeriod
			c.Services[idx].AcceptedStatusCodes = codes
			c.Services[idx].InsecureSkipVerify = insecureSkip
			// paused remains the same
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
		return
	}

	renderConfigWithError(w, "Invalid action specified")
}

func HandleForceRestartPOST(w http.ResponseWriter, r *http.Request) {
	username, _ := auth.GetSession(r)
	idx, ok := parseIndex(w, r)
	if !ok {
		return
	}

	monitor.LogAction(username, fmt.Sprintf("Requested force restart for service index %d", idx), "user")
	cfg, _ := config.LoadConfig()
	if idx < 0 || idx >= len(cfg.Services) {
		renderConfigWithError(w, fmt.Sprintf("Invalid service index: %d", idx))
		return
	}

	svc := cfg.Services[idx]
	
	// run in background to not block HTTP request
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
	cfg, _ := config.LoadConfig()
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
	cfg, _ := config.LoadConfig()
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
				fmt.Fprintf(&logsBuilder, "Invalid container name blocked from logs: %s\n\n", c)
				monitor.LogAction(username, fmt.Sprintf("Invalid container name blocked from logs: %s", c), "error")
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
	
	// Similar duration computation to ConfigGET could be factored out, omitting here for brevity as this is just explicit data display
	_ = templates.ExecuteTemplate(w, "config.html", ConfigViewData{
		Services: cfg.Services,
		Status:   *status,
		Logs:     logsBuilder.String(),
		LogsSvc:  svc.Name,
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

// JSON Endpoint for Status Fetching
func HandleAPIStatusGET(w http.ResponseWriter, r *http.Request) {
	cfg, _ := config.LoadConfig()
	status, _ := config.LoadStatus()
	
	currentTime := time.Now().Unix()

	apiStatus := APIStatusResponse{}
	for i, svc := range cfg.Services {
		if i < len(status.Services) {
			enriched := enrichServiceStatus(&status.Services[i], svc, currentTime)
			apiStatus.Services = append(apiStatus.Services, enriched)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	data := APIViewData{
		Services: cfg.Services,
		Status:   apiStatus,
	}
	
	jsonBytes, err := json.Marshal(data)
	if err == nil {
		_, _ = w.Write(jsonBytes)
	} else {
		http.Error(w, "Server error rendering JSON", http.StatusInternalServerError)
	}
}

// JSON Endpoint for live streaming logs via SSE
func HandleAPILogsStreamGET(w http.ResponseWriter, r *http.Request) {
	idx, ok := parseIndex(w, r)
	if !ok {
		return
	}

	cfg, _ := config.LoadConfig()
	if idx < 0 || idx >= len(cfg.Services) {
		http.Error(w, "Invalid service index", http.StatusBadRequest)
		return
	}

	svc := cfg.Services[idx]
	containers := strings.Split(svc.ContainerNames, ",")

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	var targetContainer string
	for _, c := range containers {
		c = strings.TrimSpace(c)
		if c != "" {
			targetContainer = c
			break
		}
	}

	if targetContainer == "" {
		fmt.Fprintf(w, "data: No valid containers found\n\n")
		flusher.Flush()
		return
	}

	if !config.IsValidContainerName(targetContainer) {
		fmt.Fprintf(w, "data: Invalid container name blocked from log stream: %s\n\n", targetContainer)
		flusher.Flush()
		monitor.LogAction("System", fmt.Sprintf("Invalid container name blocked from log stream: %s", targetContainer), "error")
		return
	}

	// #nosec G204 G702
	cmd := exec.CommandContext(r.Context(), "docker", "logs", "-f", "--tail", "50", targetContainer)
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(w, "data: Error getting logs pipe\n\n")
		flusher.Flush()
		return
	}
	
	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(w, "data: Error starting logs command\n\n")
		flusher.Flush()
		return
	}

	buf := make([]byte, 1024)
	for {
		n, err := stdoutPipe.Read(buf)
		if n > 0 {
			lines := strings.Split(string(buf[:n]), "\n")
			for _, line := range lines {
				if line != "" {
					fmt.Fprintf(w, "data: %s\n\n", strings.ReplaceAll(line, "\r", ""))
				}
			}
			flusher.Flush()
		}
		if err != nil {
			break
		}
	}
	_ = cmd.Wait()
}
