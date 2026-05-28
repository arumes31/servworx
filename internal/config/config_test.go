package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsValidContainerName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"valid name", "my-container_1.2", true},
		{"valid name uppercase", "MY_CONTAINER", true},
		{"invalid char space", "my container", false},
		{"invalid char semicolon", "my;container", false},
		{"invalid char ampersand", "my&container", false},
		{"invalid char pipe", "my|container", false},
		{"invalid char dollar", "my$container", false},
		{"invalid char backtick", "my`container`", false},
		{"invalid char newline", "my\ncontainer", false},
		{"empty name", "", false},
		{"command injection attempt", "container; rm -rf /", false},
		{"command injection attempt 2", "container $(whoami)", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidContainerName(tt.input); got != tt.expected {
				t.Errorf("IsValidContainerName(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestCaching(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldConfigDir := ConfigDir
	ConfigDir = tmpDir
	defer func() { ConfigDir = oldConfigDir }()

	// Reset cache for test
	cachedConfig = nil
	cachedStatus = nil

	cfg := &Config{
		Users: map[string]string{"admin": "hash"},
		Services: []ServiceConfig{
			{Name: "S1"},
		},
	}

	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	loaded, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if loaded.Services[0].Name != "S1" {
		t.Errorf("Expected S1, got %s", loaded.Services[0].Name)
	}

	// Modify disk file directly
	path := filepath.Join(ConfigDir, ConfigFile)
	newContent := `{"users": {"admin": "hash"}, "services": [{"name": "S2"}]}`
	if err := os.WriteFile(path, []byte(newContent), 0600); err != nil {
		t.Fatalf("Failed to modify disk file: %v", err)
	}

	// Load again, should still get S1 from cache
	loaded2, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if loaded2.Services[0].Name != "S1" {
		t.Errorf("Expected S1 from cache, but got %s from disk", loaded2.Services[0].Name)
	}

	// UpdateConfig should update cache and disk
	err = UpdateConfig(func(c *Config) {
		c.Services[0].Name = "S3"
	})
	if err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}

	loaded3, err := LoadConfig()
	if loaded3.Services[0].Name != "S3" {
		t.Errorf("Expected S3, got %s", loaded3.Services[0].Name)
	}

	// Verify disk actually has S3 now
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read disk file: %v", err)
	}
	if !strings.Contains(string(data), "S3") {
		t.Errorf("Disk file does not contain S3: %s", string(data))
	}
}
