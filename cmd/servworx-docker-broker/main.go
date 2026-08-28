package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/arumes31/servworx/internal/broker"
	"github.com/arumes31/servworx/internal/containerctl"
)

func main() {
	token, err := containerctl.ReadSecret(os.Getenv("CONTAINER_BROKER_TOKEN_FILE"), os.Getenv("CONTAINER_BROKER_TOKEN"))
	if err != nil {
		log.Fatal(err)
	}
	allowed := strings.Split(os.Getenv("SERVWORX_ALLOWED_CONTAINERS"), ",")
	brokerServer, err := broker.New(token, envOrDefault("DOCKER_SOCKET", "/var/run/docker.sock"), allowed)
	if err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		Addr:              envOrDefault("BROKER_ADDR", "0.0.0.0:8080"),
		Handler:           brokerServer.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	go func() {
		log.Printf("container broker listening on %s", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("container broker failed: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("container broker shutdown: %v", err)
	}
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
