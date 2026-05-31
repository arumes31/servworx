package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/arumes31/servworx/internal/config"
	"github.com/arumes31/servworx/internal/handlers"
	"github.com/arumes31/servworx/internal/monitor"
)

func main() {
	// 1. Initialize Default Config
	err := config.InitDefaultFiles()
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
