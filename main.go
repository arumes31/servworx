package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/arumes31/servworx/internal/config"
	"github.com/arumes31/servworx/internal/handlers"
	"github.com/arumes31/servworx/internal/monitor"
)

func main() {
	// 1. Initialize Default Config
	err := initDefaultFiles()
	if err != nil {
		log.Fatalf("Failed to initialize default config/status files: %v", err)
	}

	// 2. Load templates
	handlers.InitTemplates("/app/templates")

	// 3. Setup HTTP Mux
	mux := http.NewServeMux()
	handlers.RegisterRoutes(mux)

	server := &http.Server{
		Addr:              "0.0.0.0:5000",
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
	}

	// 4. Start Background Monitor
	monitor.LogAction("System", "servworx container started", "system")
	monitor.StartMonitoring()

	// 5. Start Server
	go func() {
		log.Println("Starting server on :5000")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// 6. Graceful Shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	monitor.LogAction("System", "Received shutdown signal, stopping container...", "system")
	monitor.StopMonitoring()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}
	monitor.LogAction("System", "Server exiting", "system")
}

func initDefaultFiles() error {
	_ = os.MkdirAll(config.ConfigDir, 0750)

	_, err := config.LoadConfig()
	if err != nil {
		if os.IsNotExist(err) {
			adminHash, _ := bcrypt.GenerateFromPassword([]byte("changeme"), bcrypt.DefaultCost)
			// Save default
			defaultCfg := &config.Config{
				Users: map[string]string{"admin": string(adminHash)},
				Services: []config.ServiceConfig{
					{
						Name:                "Service1",
						WebsiteURL:          "http://example.com",
						ContainerNames:      "service1",
						Retries:             15,
						Interval:            120,
						GracePeriod:         3600,
						AcceptedStatusCodes: []int{200},
						Paused:              false,
					},
				},
			}
			if err := config.SaveConfig(defaultCfg); err != nil {
				return fmt.Errorf("failed to save default config: %w", err)
			}
		} else {
			return fmt.Errorf("failed to load config: %w", err)
		}
	}

	_, err = config.LoadStatus()
	if err != nil {
		if os.IsNotExist(err) {
			defaultStatus := &config.Status{
				Services: []config.ServiceStatus{
					{
						Name:             "Service1",
						Status:           "Unknown",
						History:          make([]string, 0),
						LastStableStatus: "Unknown",
					},
				},
			}
			if err := config.SaveStatus(defaultStatus); err != nil {
				return fmt.Errorf("failed to save default status: %w", err)
			}
		} else {
			return fmt.Errorf("failed to load status: %w", err)
		}
	}

	return nil
}
