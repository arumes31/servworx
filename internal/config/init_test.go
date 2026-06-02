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

	err := InitDefaultFiles()
	if err != nil {
		t.Fatalf("InitDefaultFiles failed: %v", err)
	}

	// Verify config.json exists
	configPath := filepath.Join(tmpDir, ConfigFile)
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("config.json was not created")
	}

	// Verify status.json exists
	statusPath := filepath.Join(tmpDir, StatusFile)
	if _, err := os.Stat(statusPath); os.IsNotExist(err) {
		t.Error("status.json was not created")
	}

	// Load and verify config content
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if _, ok := cfg.Users["admin"]; !ok {
		t.Error("Default admin user not created")
	}

	err = bcrypt.CompareHashAndPassword([]byte(cfg.Users["admin"]), []byte("changeme"))
	if err != nil {
		t.Errorf("Default password is not 'changeme': %v", err)
	}

	if len(cfg.Services) != 1 || cfg.Services[0].Name != "Service1" {
		t.Errorf("Default service not created correctly: %+v", cfg.Services)
	}

	// Load and verify status content
	status, err := LoadStatus()
	if err != nil {
		t.Fatalf("LoadStatus failed: %v", err)
	}

	if len(status.Services) != 1 || status.Services[0].Name != "Service1" {
		t.Errorf("Default status not created correctly: %+v", status.Services)
	}
}

func TestInitDefaultFilesExisting(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := ConfigDir
	SetConfigDir(tmpDir)
	defer SetConfigDir(originalDir)

	// Create existing config
	existingCfg := &Config{
		Users: map[string]string{"existing": "user"},
	}
	if err := SaveConfig(existingCfg); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	err := InitDefaultFiles()
	if err != nil {
		t.Fatalf("InitDefaultFiles failed: %v", err)
	}

	// Verify existing config was not overwritten
	loadedCfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if _, ok := loadedCfg.Users["existing"]; !ok {
		t.Error("Existing config was overwritten")
	}
	if _, ok := loadedCfg.Users["admin"]; ok {
		t.Error("Admin user was added to existing config")
	}
}

func TestInitDefaultFilesMkdirError(t *testing.T) {
	// Create a file where a directory should be
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "blocked")
	if err := os.WriteFile(filePath, []byte("not a dir"), 0644); err != nil {
		t.Fatalf("Failed to create blocking file: %v", err)
	}

	originalDir := ConfigDir
	SetConfigDir(filepath.Join(filePath, "subdir")) // MkdirAll should fail
	defer SetConfigDir(originalDir)

	err := InitDefaultFiles()
	if err == nil {
		t.Error("Expected error when MkdirAll fails, got nil")
	}
}
