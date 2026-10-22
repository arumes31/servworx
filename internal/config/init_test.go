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

	t.Setenv("ADMIN_PASSWORD", "initial-secret-1")

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
	err = bcrypt.CompareHashAndPassword([]byte(cfg.Users["admin"]), []byte("initial-secret-1"))
	if err != nil {
		t.Errorf("Admin password hash does not match ADMIN_PASSWORD: %v", err)
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

func TestInitDefaultFiles_GeneratedPassword(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := ConfigDir
	SetConfigDir(tmpDir)
	defer SetConfigDir(originalDir)
	ClearCache()
	defer ClearCache()
	t.Setenv("ADMIN_PASSWORD", "")

	if err := InitDefaultFiles(); err != nil {
		t.Fatalf("InitDefaultFiles failed: %v", err)
	}

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load created config: %v", err)
	}
	if bcrypt.CompareHashAndPassword([]byte(cfg.Users["admin"]), []byte("changeme")) == nil {
		t.Error("Default admin password must not be the well-known 'changeme'")
	}
}

func TestInitialAdminPassword(t *testing.T) {
	t.Setenv("ADMIN_PASSWORD", "short")
	if _, _, err := initialAdminPassword(); err == nil {
		t.Error("expected error for ADMIN_PASSWORD shorter than 8 characters")
	}

	t.Setenv("ADMIN_PASSWORD", "")
	p1, generated, err := initialAdminPassword()
	if err != nil || !generated || len(p1) < 16 {
		t.Fatalf("expected generated password, got %q generated=%v err=%v", p1, generated, err)
	}
	p2, _, _ := initialAdminPassword()
	if p1 == p2 {
		t.Error("expected different random passwords")
	}
}
