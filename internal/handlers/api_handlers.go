package handlers

import (
	"encoding/json"
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

type APIServiceStatus struct {
	config.ServiceStatus
	History []string `json:"history"`
}

type APIStatusResponse struct {
	Services []APIServiceStatus `json:"services"`
}

type APIViewData struct {
	Services []config.ServiceConfig `json:"services"`
	Status   APIStatusResponse      `json:"status"`
}

func HandleAPIStatusGET(w http.ResponseWriter, r *http.Request) {
	cfg, errCfg := config.LoadConfig()
	status, errStatus := config.LoadStatus()

	if errCfg != nil || errStatus != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error": "Failed to load configuration"}`)
		return
	}

	currentTime := time.Now().Unix()

	for i, svc := range cfg.Services {
		if i < len(status.Services) {
			s := &status.Services[i]
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
		}
	}

	apiStatus := APIStatusResponse{}
	for i, s := range status.Services {
		history := []string{}
		if i < len(cfg.Services) {
			history = monitor.GetHistory(cfg.Services[i].Name)
		}
		apiStatus.Services = append(apiStatus.Services, APIServiceStatus{
			ServiceStatus: s,
			History:       history,
		})
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
			if config.IsValidContainerName(c) {
				targetContainer = c
				break
			} else {
				monitor.LogAction("System", fmt.Sprintf("Invalid container name blocked from log stream: %s", c), "error")
			}
		}
	}

	if targetContainer == "" {
		fmt.Fprintf(w, "data: No valid containers found\n\n")
		flusher.Flush()
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

func HandleAPINotificationTestPOST(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10MB limit
	_ = r.ParseForm()

	idxStr := r.FormValue("index")
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"success": false, "error": "Invalid service index"}`)
		return
	}

	provider := r.FormValue("provider")
	if provider == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"success": false, "error": "Provider not specified"}`)
		return
	}

	cfg, err := config.LoadConfig()
	if err != nil || idx < 0 || idx >= len(cfg.Services) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"success": false, "error": "Service not found"}`)
		return
	}

	svc := cfg.Services[idx]

	err = monitor.SendTestNotification(svc, provider)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		// #nosec G705
		fmt.Fprintf(w, `{"success": false, "error": %q}`, err.Error())
	} else {
		fmt.Fprintf(w, `{"success": true, "message": "Test alert dispatched successfully!"}`)
	}
}

func HandleAPISnoozePOST(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10MB limit
	_ = r.ParseForm()

	username, _ := auth.GetSession(r)
	idx, ok := parseIndex(w, r)
	if !ok {
		return
	}

	durationStr := r.FormValue("duration")
	durationMins, err := strconv.Atoi(durationStr)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"success": false, "error": "Invalid duration"}`)
		return
	}

	var snoozeUntil int64
	if durationMins > 0 {
		snoozeUntil = time.Now().Unix() + int64(durationMins*60)
	} else {
		snoozeUntil = 0
	}

	var svcName string
	_ = config.UpdateConfig(func(c *config.Config) {
		if idx >= 0 && idx < len(c.Services) {
			c.Services[idx].AlertSnoozeUntil = snoozeUntil
			svcName = c.Services[idx].Name
		}
	})

	action := "Alerts snoozed"
	if snoozeUntil == 0 {
		action = "Alerts unsnoozed"
	}
	monitor.LogAction(username, fmt.Sprintf("%s for service %s", action, svcName), "user")
	monitor.RestartMonitoring()

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"success": true, "message": %q}`, action)
}
