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

func TestCachingAndDeepCopy(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "servworx-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	origConfigDir := ConfigDir
	ConfigDir = tmpDir
	defer func() { ConfigDir = origConfigDir }()

	// Reset cache
	cachedConfig = nil
	cachedStatus = nil

	// 1. Test Status caching
	status := &Status{
		Services: []ServiceStatus{
			{Name: "Service1", Status: "Up"},
		},
	}
	if err := SaveStatus(status); err != nil {
		t.Fatalf("SaveStatus failed: %v", err)
	}

	loaded1, err := LoadStatus()
	if err != nil {
		t.Fatalf("LoadStatus 1 failed: %v", err)
	}

	// Modify loaded1
	loaded1.Services[0].Status = "Down"

	loaded2, err := LoadStatus()
	if err != nil {
		t.Fatalf("LoadStatus 2 failed: %v", err)
	}

	if loaded2.Services[0].Status != "Up" {
		t.Errorf("DeepCopy failed: modification to returned object affected cache. Got %s, want Up", loaded2.Services[0].Status)
	}

	// 2. Test UpdateStatus updates cache
	err = UpdateStatus(func(s *Status) {
		s.Services[0].Status = "Maintenance"
	})
	if err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}

	loaded3, err := LoadStatus()
	if err != nil {
		t.Fatalf("LoadStatus 3 failed: %v", err)
	}

	if loaded3.Services[0].Status != "Maintenance" {
		t.Errorf("UpdateStatus did not update cache correctly. Got %s, want Maintenance", loaded3.Services[0].Status)
	}
}
