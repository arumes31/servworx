package config

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestInitDefaultFiles(t *testing.T) {
	t.Setenv("SERVWORX_ADMIN_PASSWORD", "correct-horse-battery-staple")
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
	err = bcrypt.CompareHashAndPassword([]byte(cfg.Users["admin"]), []byte("correct-horse-battery-staple"))
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

func TestInitDefaultFilesRequiresStrongBootstrapPassword(t *testing.T) {
	t.Setenv("SERVWORX_ADMIN_PASSWORD", "")
	t.Setenv("SERVWORX_ADMIN_PASSWORD_FILE", "")
	originalDir := ConfigDir
	SetConfigDir(t.TempDir())
	ClearCache()
	t.Cleanup(func() {
		SetConfigDir(originalDir)
		ClearCache()
	})

	if err := InitDefaultFiles(); err == nil {
		t.Fatal("expected missing bootstrap password to fail")
	}
}

func TestInitDefaultFilesRotatesLegacyDefault(t *testing.T) {
	t.Setenv("SERVWORX_ADMIN_PASSWORD", "replacement-password-unique")
	originalDir := ConfigDir
	SetConfigDir(t.TempDir())
	ClearCache()
	t.Cleanup(func() {
		SetConfigDir(originalDir)
		ClearCache()
	})

	legacy, err := bcrypt.GenerateFromPassword([]byte("changeme"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveConfig(&Config{Users: map[string]string{"admin": string(legacy)}}); err != nil {
		t.Fatal(err)
	}
	if err := InitDefaultFiles(); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if bcrypt.CompareHashAndPassword([]byte(cfg.Users["admin"]), []byte("changeme")) == nil {
		t.Fatal("legacy default password remained valid")
	}
	if bcrypt.CompareHashAndPassword([]byte(cfg.Users["admin"]), []byte("replacement-password-unique")) != nil {
		t.Fatal("replacement password was not installed")
	}
}
