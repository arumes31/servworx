package monitor

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/arumes31/servworx/internal/config"
)

var (
	stopChan = make(chan struct{})
	wg       sync.WaitGroup

	defaultHttpClient = &http.Client{
		Timeout: 5 * time.Second,
	}
	insecureHttpClient = &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			// #nosec G402
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// In-memory health check history (not persisted to disk)
	healthHistory = make(map[string][]string)
	historyMutex  sync.RWMutex

	// color codes
	colorGreen  = "\033[92m"
	colorBlue   = "\033[94m"
	colorYellow = "\033[93m"
	colorRed    = "\033[91m"
	colorReset  = "\033[0m"
)

// PushHistory adds a status entry to the in-memory history for a service.
func PushHistory(serviceName, status string) {
	historyMutex.Lock()
	defer historyMutex.Unlock()
	healthHistory[serviceName] = append(healthHistory[serviceName], status)
	if len(healthHistory[serviceName]) > 30 {
		healthHistory[serviceName] = healthHistory[serviceName][1:]
	}
}

// GetHistory returns a copy of the in-memory history for a service.
func GetHistory(serviceName string) []string {
	historyMutex.RLock()
	defer historyMutex.RUnlock()
	h := healthHistory[serviceName]
	if h == nil {
		return []string{}
	}
	result := make([]string, len(h))
	copy(result, h)
	return result
}

func LogAction(username, action, logType string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	color := colorReset
	switch logType {
	case "user":
		color = colorGreen
	case "system":
		color = colorBlue
	case "status":
		if strings.Contains(action, "Down") {
			color = colorRed
		} else {
			color = colorYellow
		}
	case "error":
		color = colorRed
	}
	fmt.Printf("%s[%s] %s: %s%s\n", color, timestamp, username, action, colorReset)
}

func checkWebsite(url string, acceptedCodes []int, insecureSkip bool) (bool, string) {
	httpClient := defaultHttpClient
	if insecureSkip {
		httpClient = insecureHttpClient
	}
	resp, err := httpClient.Head(url)
	if err != nil {
		return false, fmt.Sprintf("Website is unreachable: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Check if the HEAD response code is already accepted before falling back to GET
	for _, code := range acceptedCodes {
		if resp.StatusCode == code {
			return true, fmt.Sprintf("Website returned status %d (accepted)", resp.StatusCode)
		}
	}

	// Only fall back to GET if HEAD returned 405/501 and the code wasn't explicitly accepted
	if resp.StatusCode == 405 || resp.StatusCode == 501 {
		resp2, err2 := httpClient.Get(url)
		if err2 != nil {
			return false, fmt.Sprintf("Website is unreachable: %v", err2)
		}
		defer func() { _ = resp2.Body.Close() }()
		resp = resp2
	}

	for _, code := range acceptedCodes {
		if resp.StatusCode == code {
			return true, fmt.Sprintf("Website returned status %d (accepted)", resp.StatusCode)
		}
	}
	return false, fmt.Sprintf("Website returned status %d (not accepted)", resp.StatusCode)
}

func restartContainers(containerNames, serviceName string) int64 {
	LogAction("System", fmt.Sprintf("Restarting Docker containers for %s", serviceName), "error")
	containers := strings.Split(containerNames, ",")
	for _, c := range containers {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !config.IsValidContainerName(c) {
			fmt.Printf("Invalid container name blocked from restart: %s\n", c)
			LogAction("System", fmt.Sprintf("Invalid container name blocked from restart: %s", c), "error")
			continue
		}
		fmt.Printf("Executing 'docker restart %s'\n", c)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		// #nosec G204
		cmd := exec.CommandContext(ctx, "docker", "restart", c)
		if err := cmd.Run(); err != nil {
			fmt.Printf("Error restarting %s: %v\n", c, err)
		} else {
			fmt.Printf("Completed 'docker restart %s'\n", c)
		}
		cancel()
	}

	lastRestart := time.Now().Unix()
	_ = config.UpdateStatus(func(s *config.Status) {
		for i := range s.Services {
			if s.Services[i].Name == serviceName {
				nowStr := time.Now().Format("2006-01-02 15:04:05")
				s.Services[i].LastFailure = &nowStr
				LogAction("System", fmt.Sprintf("Updated last_failure for %s to %s", serviceName, nowStr), "system")
			}
		}
	})
	return lastRestart
}

func getRestartFilename(name string) string {
	safeName := base64.URLEncoding.EncodeToString([]byte(name))
	return fmt.Sprintf("last_restart_%s.txt", safeName)
}

func readLastRestart(name string) int64 {
	path := filepath.Join(config.ConfigDir, getRestartFilename(name))
	// #nosec G304
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	val, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}
	return val
}

func writeLastRestart(name string, val int64) {
	path := filepath.Join(config.ConfigDir, getRestartFilename(name))
	_ = os.WriteFile(path, []byte(fmt.Sprintf("%d", val)), 0600)
}

func updateServiceStatus(serviceName, status string) {
	_ = config.UpdateStatus(func(s *config.Status) {
		for i := range s.Services {
			if s.Services[i].Name == serviceName {
				if status == "Checking" {
					s.Services[i].Status = "Checking"
					LogAction("System", fmt.Sprintf("Service %s status: Checking", serviceName), "status")
					return
				}

				oldStatusStr := s.Services[i].LastStableStatus
				if oldStatusStr == "" {
					oldStatusStr = s.Services[i].Status
				}

				s.Services[i].Status = status

				if status != oldStatusStr {
					nowStr := time.Now().Format("2006-01-02 15:04:05")
					if status == "Down" && oldStatusStr == "Up" {
						s.Services[i].DownSince = &nowStr
						s.Services[i].UpSince = nil
						s.Services[i].LastFailure = &nowStr
						LogAction("System", fmt.Sprintf("Updated down_since for %s to %s", serviceName, nowStr), "system")
					} else if status == "Up" && oldStatusStr == "Down" {
						s.Services[i].UpSince = &nowStr
						s.Services[i].DownSince = nil
						LogAction("System", fmt.Sprintf("Updated up_since for %s to %s", serviceName, nowStr), "system")
					}
				}
				s.Services[i].LastStableStatus = status
				LogAction("System", fmt.Sprintf("Service %s status: %s", serviceName, status), "status")
				break
			}
		}
	})

	if status != "Checking" {
		PushHistory(serviceName, status)
	}
}

func checkWithRetries(svc *config.ServiceConfig) (bool, bool) {
	success := false
	var message string
	for i := 1; i <= svc.Retries; i++ {
		success, message = checkWebsite(svc.WebsiteURL, svc.AcceptedStatusCodes, svc.InsecureSkipVerify)

		status := "Down"
		if success {
			status = "Up"
		}
		updateServiceStatus(svc.Name, status)

		fmt.Printf("%s: %s\n", svc.Name, message)
		if success {
			return true, false
		} else if i < svc.Retries {
			fmt.Printf("%s: Retry %d/%d failed, retrying in %d seconds...\n", svc.Name, i, svc.Retries, svc.Interval)

			select {
			case <-time.After(time.Duration(svc.Interval) * time.Second):
				// waited
			case <-stopChan:
				return false, true
			}
		}
	}
	fmt.Printf("%s: Max retries (%d) reached.\n", svc.Name, svc.Retries)
	return false, false
}

func handleServiceFailure(svc *config.ServiceConfig, restartAllowed bool, remainingGrace int64, lastRestart int64) int64 {
	if restartAllowed {
		newRestart := restartContainers(svc.ContainerNames, svc.Name)
		writeLastRestart(svc.Name, newRestart)
		return newRestart
	} else {
		fmt.Printf("%s: Restart not allowed yet. Remaining grace period: %d seconds.\n", svc.Name, remainingGrace)
		LogAction("System", fmt.Sprintf("Service %s: Restart not allowed, remaining grace period: %d seconds", svc.Name, remainingGrace), "error")
		return lastRestart
	}
}

func monitorService(svc config.ServiceConfig) {
	defer wg.Done()

	lastRestart := readLastRestart(svc.Name)

	ticker := time.NewTicker(time.Duration(svc.Interval) * time.Second)
	defer ticker.Stop()

	for {
		// Read latest config for this service in case it changed (like paused)
		var currentSvc *config.ServiceConfig
		cfg, err := config.LoadConfig()
		if err == nil {
			for _, s := range cfg.Services {
				if s.Name == svc.Name {
					currentSvc = &s
					break
				}
			}
		}

		if currentSvc == nil {
			// Service was deleted, exit goroutine
			return
		}

		if currentSvc.Paused {
			select {
			case <-stopChan:
				return
			case <-ticker.C:
				continue
			}
		}

		now := time.Now().Unix()
		timeSinceLastRestart := now - lastRestart
		restartAllowed := timeSinceLastRestart >= int64(currentSvc.GracePeriod)
		remainingGrace := int64(currentSvc.GracePeriod) - timeSinceLastRestart
		if remainingGrace < 0 {
			remainingGrace = 0
		}

		updateServiceStatus(currentSvc.Name, "Checking")

		success, stopped := checkWithRetries(currentSvc)
		if stopped {
			return
		}

		if !success {
			lastRestart = handleServiceFailure(currentSvc, restartAllowed, remainingGrace, lastRestart)
		}

		select {
		case <-stopChan:
			return
		case <-ticker.C:
			// wait for next interval
		}
	}
}

func StartMonitoring() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Printf("Failed to load config for monitoring: %v", err)
		return
	}

	// Rebuild status.json to match config.json order
	_ = config.UpdateStatus(func(s *config.Status) {
		var newStatus []config.ServiceStatus
		existing := make(map[string]config.ServiceStatus)
		for _, es := range s.Services {
			existing[es.Name] = es
		}

		for _, svc := range cfg.Services {
			if es, ok := existing[svc.Name]; ok {
				if es.LastStableStatus == "" {
					es.LastStableStatus = es.Status
					if es.LastStableStatus == "" {
						es.LastStableStatus = "Unknown"
					}
				}
				newStatus = append(newStatus, es)
			} else {
				newStatus = append(newStatus, config.ServiceStatus{
					Name:             svc.Name,
					Status:           "Unknown",
					LastStableStatus: "Unknown",
				})
				LogAction("System", fmt.Sprintf("Initialized status for new service: %s", svc.Name), "system")
			}
		}
		s.Services = newStatus
	})

	LogAction("System", "Monitoring threads started", "system")

	// Start threads
	for _, svc := range cfg.Services {
		wg.Add(1)
		go monitorService(svc)
	}
}

func StopMonitoring() {
	close(stopChan) // broadcast stop to all goroutines
	wg.Wait()
	LogAction("System", "Monitoring threads stopped", "system")
	// Recreate channel for potential restart in UI actions
	stopChan = make(chan struct{})
}

func RestartMonitoring() {
	StopMonitoring()
	StartMonitoring()
}
