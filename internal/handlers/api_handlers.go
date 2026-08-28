package handlers

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
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
		_, _ = fmt.Fprintf(w, `{"error": "Failed to load configuration"}`)
		return
	}

	currentTime := time.Now().Unix()

	apiStatus := APIStatusResponse{}
	for i := range cfg.Services {
		if i < len(status.Services) {
			history := enrichServiceStatus(cfg.Services[i], &status.Services[i], currentTime)
			apiStatus.Services = append(apiStatus.Services, APIServiceStatus{
				ServiceStatus: status.Services[i],
				History:       history,
			})
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

func HandleAPILogsStreamGET(w http.ResponseWriter, r *http.Request) {
	username, _ := auth.GetSession(r)
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
				monitor.LogAction(username, fmt.Sprintf("Invalid container name blocked from log stream: %s", c), "error")
			}
		}
	}

	if targetContainer == "" {
		_, _ = fmt.Fprintf(w, "data: No valid containers found\n\n")
		flusher.Flush()
		return
	}

	logStream, err := containerController.Logs(r.Context(), targetContainer, 50, true)
	if err != nil {
		_, _ = fmt.Fprintf(w, "data: Error opening container logs\n\n")
		flusher.Flush()
		return
	}
	defer func() { _ = logStream.Close() }()
	scanner := bufio.NewScanner(logStream)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		line := strings.ReplaceAll(scanner.Text(), "\r", "")
		if line != "" {
			_, _ = fmt.Fprintf(w, "data: %s\n\n", line)
			flusher.Flush()
		}
	}
}

func HandleAPINotificationTestPOST(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form body", http.StatusBadRequest)
		return
	}

	idxStr := r.FormValue("index")
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, `{"success": false, "error": "Invalid service index"}`)
		return
	}

	provider := r.FormValue("provider")
	if provider == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, `{"success": false, "error": "Provider not specified"}`)
		return
	}

	cfg, err := config.LoadConfig()
	if err != nil || idx < 0 || idx >= len(cfg.Services) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, `{"success": false, "error": "Service not found"}`)
		return
	}

	svc := cfg.Services[idx]

	err = monitor.SendTestNotification(svc, provider)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		// #nosec G705
		_, _ = fmt.Fprintf(w, `{"success": false, "error": %q}`, err.Error())
	} else {
		_, _ = fmt.Fprintf(w, `{"success": true, "message": "Test alert dispatched successfully!"}`)
	}
}

func HandleAPISnoozePOST(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form body", http.StatusBadRequest)
		return
	}

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
		_, _ = fmt.Fprintf(w, `{"success": false, "error": "Invalid duration"}`)
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
	restartMonitoring()

	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"success": true, "message": %q}`, action)
}
