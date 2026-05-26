package config

import (
	"os"
	"reflect"
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

func TestSetConfigDir(t *testing.T) {
	oldDir := ConfigDir
	t.Cleanup(func() {
		ConfigDir = oldDir
	})

	newDir := "/tmp/test-config"
	SetConfigDir(newDir)
	if ConfigDir != newDir {
		t.Errorf("SetConfigDir(%q) = %q, want %q", newDir, ConfigDir, newDir)
	}
}

func TestLoadSaveConfig(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir := ConfigDir
	t.Cleanup(func() {
		ConfigDir = oldDir
	})
	ConfigDir = tmpDir

	cfg := &Config{
		Users: map[string]string{"admin": "password"},
		Services: []ServiceConfig{
			{
				Name: "TestService",
			},
		},
	}

	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	loaded, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if !reflect.DeepEqual(cfg.Users, loaded.Users) {
		t.Errorf("Users mismatch: got %v, want %v", loaded.Users, cfg.Users)
	}

	if len(loaded.Services) != 1 {
		t.Fatalf("Expected 1 service, got %d", len(loaded.Services))
	}

	if loaded.Services[0].Name != "TestService" {
		t.Errorf("Service name mismatch: got %s, want TestService", loaded.Services[0].Name)
	}

	// Verify default AcceptedStatusCodes
	expectedCodes := []int{200}
	if !reflect.DeepEqual(loaded.Services[0].AcceptedStatusCodes, expectedCodes) {
		t.Errorf("AcceptedStatusCodes mismatch: got %v, want %v", loaded.Services[0].AcceptedStatusCodes, expectedCodes)
	}
}

func TestLoadSaveStatus(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir := ConfigDir
	t.Cleanup(func() {
		ConfigDir = oldDir
	})
	ConfigDir = tmpDir

	status := &Status{
		Services: []ServiceStatus{
			{
				Name:   "TestService",
				Status: "Up",
			},
		},
	}

	if err := SaveStatus(status); err != nil {
		t.Fatalf("SaveStatus failed: %v", err)
	}

	loaded, err := LoadStatus()
	if err != nil {
		t.Fatalf("LoadStatus failed: %v", err)
	}

	if len(loaded.Services) != 1 {
		t.Fatalf("Expected 1 service status, got %d", len(loaded.Services))
	}

	if loaded.Services[0].Name != "TestService" || loaded.Services[0].Status != "Up" {
		t.Errorf("Status mismatch: got %+v, want %+v", loaded.Services[0], status.Services[0])
	}
}

func TestUpdateConfig(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir := ConfigDir
	t.Cleanup(func() {
		ConfigDir = oldDir
	})
	ConfigDir = tmpDir

	// Test update non-existent file
	err := UpdateConfig(func(cfg *Config) {
		cfg.Users["newuser"] = "newpass"
	})
	if err != nil {
		t.Fatalf("UpdateConfig (initial) failed: %v", err)
	}

	loaded, _ := LoadConfig()
	if loaded.Users["newuser"] != "newpass" {
		t.Errorf("Initial UpdateConfig failed to set user")
	}

	// Test update existing file
	err = UpdateConfig(func(cfg *Config) {
		cfg.Users["another"] = "pass"
	})
	if err != nil {
		t.Fatalf("UpdateConfig (existing) failed: %v", err)
	}

	loaded, _ = LoadConfig()
	if loaded.Users["another"] != "pass" || loaded.Users["newuser"] != "newpass" {
		t.Errorf("UpdateConfig failed to persist changes correctly")
	}
}

func TestUpdateStatus(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir := ConfigDir
	t.Cleanup(func() {
		ConfigDir = oldDir
	})
	ConfigDir = tmpDir

	// Test update non-existent file
	err := UpdateStatus(func(s *Status) {
		s.Services = append(s.Services, ServiceStatus{Name: "NewSvc", Status: "Down"})
	})
	if err != nil {
		t.Fatalf("UpdateStatus (initial) failed: %v", err)
	}

	loaded, _ := LoadStatus()
	if len(loaded.Services) != 1 || loaded.Services[0].Name != "NewSvc" {
		t.Errorf("Initial UpdateStatus failed")
	}

	// Test update existing file
	err = UpdateStatus(func(s *Status) {
		s.Services[0].Status = "Up"
	})
	if err != nil {
		t.Fatalf("UpdateStatus (existing) failed: %v", err)
	}

	loaded, _ = LoadStatus()
	if loaded.Services[0].Status != "Up" {
		t.Errorf("UpdateStatus failed to update existing status")
	}
}

func TestLoadNonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir := ConfigDir
	t.Cleanup(func() {
		ConfigDir = oldDir
	})
	ConfigDir = tmpDir

	_, err := LoadConfig()
	if !os.IsNotExist(err) {
		t.Errorf("LoadConfig non-existent: expected IsNotExist error, got %v", err)
	}

	_, err = LoadStatus()
	if !os.IsNotExist(err) {
		t.Errorf("LoadStatus non-existent: expected IsNotExist error, got %v", err)
	}
}
