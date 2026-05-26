package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/arumes31/servworx/internal/config"
	"golang.org/x/crypto/bcrypt"
)

func TestInitDefaultFiles(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "servworx-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Save original config directory and restore it after test
	originalConfigDir := config.ConfigDir
	config.ConfigDir = tmpDir
	defer func() { config.ConfigDir = originalConfigDir }()

	// Run initDefaultFiles
	err = initDefaultFiles()
	if err != nil {
		t.Fatalf("initDefaultFiles failed: %v", err)
	}

	// Verify config file exists
	configPath := filepath.Join(tmpDir, config.ConfigFile)
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Errorf("config file was not created at %s", configPath)
	}

	// Verify status file exists
	statusPath := filepath.Join(tmpDir, config.StatusFile)
	if _, err := os.Stat(statusPath); os.IsNotExist(err) {
		t.Errorf("status file was not created at %s", statusPath)
	}

	// Load and verify config content
	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("failed to load created config: %v", err)
	}
	hash, ok := cfg.Users["admin"]
	if !ok {
		t.Errorf("expected admin user to be present in config")
	}
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte("changeme"))
	if err != nil {
		t.Errorf("admin password hash mismatch: %v", err)
	}

	if len(cfg.Services) != 1 || cfg.Services[0].Name != "Service1" {
		t.Errorf("expected Service1 to be present in config")
	}

	// Load and verify status content
	status, err := config.LoadStatus()
	if err != nil {
		t.Fatalf("failed to load created status: %v", err)
	}
	if len(status.Services) != 1 || status.Services[0].Name != "Service1" {
		t.Errorf("expected Service1 to be present in status")
	}
}
