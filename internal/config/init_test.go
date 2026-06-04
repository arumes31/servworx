package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitDefaultFiles(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := ConfigDir
	SetConfigDir(tmpDir)
	t.Cleanup(func() { SetConfigDir(originalDir) })

	// Test creation when files don't exist
	err := InitDefaultFiles()
	if err != nil {
		t.Fatalf("InitDefaultFiles failed: %v", err)
	}

	configPath := filepath.Join(tmpDir, ConfigFile)
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Errorf("Config file was not created")
	}

	statusPath := filepath.Join(tmpDir, StatusFile)
	if _, err := os.Stat(statusPath); os.IsNotExist(err) {
		t.Errorf("Status file was not created")
	}

	// Test when files already exist (should not overwrite/error)
	err = InitDefaultFiles()
	if err != nil {
		t.Fatalf("InitDefaultFiles failed on second run: %v", err)
	}
}

func TestInitConfigError(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := ConfigDir
	SetConfigDir(tmpDir)
	t.Cleanup(func() { SetConfigDir(originalDir) })

	err := os.MkdirAll(filepath.Join(tmpDir, ConfigFile), 0750)
	if err != nil {
		t.Fatal(err)
	}

	err = initConfig()
	if err == nil {
		t.Errorf("Expected error when config file is a directory")
	}
}

func TestInitStatusError(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := ConfigDir
	SetConfigDir(tmpDir)
	t.Cleanup(func() { SetConfigDir(originalDir) })

	err := os.MkdirAll(filepath.Join(tmpDir, StatusFile), 0750)
	if err != nil {
		t.Fatal(err)
	}

	err = initStatus()
	if err == nil {
		t.Errorf("Expected error when status file is a directory")
	}
}

func TestInitDefaultFilesMkdirError(t *testing.T) {
	tmpDir := t.TempDir()
	blockedDir := filepath.Join(tmpDir, "blocked")
	if err := os.WriteFile(blockedDir, []byte("file"), 0600); err != nil {
		t.Fatal(err)
	}

	originalDir := ConfigDir
	SetConfigDir(blockedDir)
	t.Cleanup(func() { SetConfigDir(originalDir) })

	err := InitDefaultFiles()
	if err == nil {
		t.Errorf("Expected error when ConfigDir is a file")
	}
}
