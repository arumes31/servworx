package config

import (
	"os"
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
	tmpDir, err := os.MkdirTemp("", "servworx_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	SetConfigDir(tmpDir)

	cfg := &Config{
		Users: map[string]string{"admin": "hash"},
		Services: []ServiceConfig{
			{Name: "S1", Interval: 10},
		},
	}

	if err := SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}

	// Load from cache
	loaded, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}

	if loaded.Services[0].Name != "S1" {
		t.Errorf("expected S1, got %s", loaded.Services[0].Name)
	}

	// Modify loaded config (deep copy should prevent affecting cache)
	loaded.Services[0].Name = "Modified"

	loaded2, _ := LoadConfig()
	if loaded2.Services[0].Name != "S1" {
		t.Errorf("expected cache to remain S1, but got %s", loaded2.Services[0].Name)
	}

	// Test GetServiceConfig
	svc, err := GetServiceConfig("S1")
	if err != nil {
		t.Fatal(err)
	}
	if svc.Interval != 10 {
		t.Errorf("expected 10, got %d", svc.Interval)
	}
}
