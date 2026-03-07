package monitor

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"context"
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

	// color codes
	colorGreen  = "\033[92m"
	colorBlue   = "\033[94m"
	colorYellow = "\033[93m"
	colorRed    = "\033[91m"
	colorReset  = "\033[0m"
)

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
	// #nosec G402
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkip},
		},
	}
	resp, err := httpClient.Head(url)
	if err != nil {
		return false, fmt.Sprintf("Website is unreachable: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

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

		_ = config.UpdateStatus(func(s *config.Status) {
			for i := range s.Services {
				if s.Services[i].Name == currentSvc.Name {
					s.Services[i].Status = "Checking"
					LogAction("System", fmt.Sprintf("Service %s status: Checking", currentSvc.Name), "status")
					break
				}
			}
		})

		success := false
		var message string
		for i := 1; i <= currentSvc.Retries; i++ {
			success, message = checkWebsite(currentSvc.WebsiteURL, currentSvc.AcceptedStatusCodes, currentSvc.InsecureSkipVerify)

			_ = config.UpdateStatus(func(s *config.Status) {
				for j := range s.Services {
					if s.Services[j].Name == currentSvc.Name {
						oldStatusStr := s.Services[j].LastStableStatus
						if oldStatusStr == "" {
							oldStatusStr = s.Services[j].Status
						}
						
						newStatus := "Down"
						if success {
							newStatus = "Up"
						}
						s.Services[j].Status = newStatus
						
						s.Services[j].History = append(s.Services[j].History, newStatus)
						if len(s.Services[j].History) > 30 {
							s.Services[j].History = s.Services[j].History[1:]
						}

						if newStatus != oldStatusStr {
							nowStr := time.Now().Format("2006-01-02 15:04:05")
							if newStatus == "Down" && oldStatusStr == "Up" {
								s.Services[j].DownSince = &nowStr
								s.Services[j].UpSince = nil
								s.Services[j].LastFailure = &nowStr
								LogAction("System", fmt.Sprintf("Updated down_since for %s to %s", currentSvc.Name, nowStr), "system")
							} else if newStatus == "Up" && oldStatusStr == "Down" {
								s.Services[j].UpSince = &nowStr
								s.Services[j].DownSince = nil
								LogAction("System", fmt.Sprintf("Updated up_since for %s to %s", currentSvc.Name, nowStr), "system")
							}
						}
						s.Services[j].LastStableStatus = newStatus
						LogAction("System", fmt.Sprintf("Service %s status: %s", currentSvc.Name, newStatus), "status")
						break
					}
				}
			})

			fmt.Printf("%s: %s\n", currentSvc.Name, message)
			if success {
				break
			} else if i < currentSvc.Retries {
				fmt.Printf("%s: Retry %d/%d failed, retrying in %d seconds...\n", currentSvc.Name, i, currentSvc.Retries, currentSvc.Interval)
				
				select {
				case <-time.After(time.Duration(currentSvc.Interval) * time.Second):
					// waited
				case <-stopChan:
					return
				}
			}
		}

		if !success {
			fmt.Printf("%s: Max retries (%d) reached.\n", currentSvc.Name, currentSvc.Retries)
			if restartAllowed {
				lastRestart = restartContainers(currentSvc.ContainerNames, currentSvc.Name)
				writeLastRestart(currentSvc.Name, lastRestart)
			} else {
				fmt.Printf("%s: Restart not allowed yet. Remaining grace period: %d seconds.\n", currentSvc.Name, remainingGrace)
				LogAction("System", fmt.Sprintf("Service %s: Restart not allowed, remaining grace period: %d seconds", currentSvc.Name, remainingGrace), "error")
			}
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
					History:          make([]string, 0),
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
