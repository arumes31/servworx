package config

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestInitDefaultFiles(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := ConfigDir
	SetConfigDir(tmpDir)
	defer SetConfigDir(originalDir)

	// Test 1: Files don't exist
	err := InitDefaultFiles()
	if err != nil {
		t.Fatalf("InitDefaultFiles failed: %v", err)
	}

	configPath := filepath.Join(tmpDir, ConfigFile)
	statusPath := filepath.Join(tmpDir, StatusFile)

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Errorf("Config file was not created")
	}
	if _, err := os.Stat(statusPath); os.IsNotExist(err) {
		t.Errorf("Status file was not created")
	}

	// Verify config content
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load created config: %v", err)
	}
	if _, ok := cfg.Users["admin"]; !ok {
		t.Errorf("Default admin user not found")
	}
	err = bcrypt.CompareHashAndPassword([]byte(cfg.Users["admin"]), []byte("changeme"))
	if err != nil {
		t.Errorf("Default password hash is incorrect: %v", err)
	}
	if len(cfg.Services) != 1 || cfg.Services[0].Name != "Service1" {
		t.Errorf("Default service not found or incorrect")
	}

	// Verify status content
	status, err := LoadStatus()
	if err != nil {
		t.Fatalf("Failed to load created status: %v", err)
	}
	if len(status.Services) != 1 || status.Services[0].Name != "Service1" {
		t.Errorf("Default status service not found or incorrect")
	}

	// Test 2: Files already exist (should not overwrite with defaults if we modify them)
	err = UpdateConfig(func(c *Config) {
		c.Users["newuser"] = "hash"
	})
	if err != nil {
		t.Fatalf("Failed to update config: %v", err)
	}

	err = InitDefaultFiles()
	if err != nil {
		t.Fatalf("InitDefaultFiles failed on second run: %v", err)
	}

	cfg, _ = LoadConfig()
	if _, ok := cfg.Users["newuser"]; !ok {
		t.Errorf("InitDefaultFiles overwrote existing config")
	}
}
