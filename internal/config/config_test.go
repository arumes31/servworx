package config

import (
	"os"
	"path/filepath"
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

func TestConfigOperations(t *testing.T) {
	origConfigDir := ConfigDir
	defer func() { ConfigDir = origConfigDir }()

	tmpDir := t.TempDir()
	SetConfigDir(tmpDir)

	if ConfigDir != tmpDir {
		t.Errorf("expected ConfigDir to be %s, got %s", tmpDir, ConfigDir)
	}

	// Test LoadConfig on non-existent file
	_, err := LoadConfig()
	if !os.IsNotExist(err) {
		t.Errorf("expected error to be IsNotExist, got %v", err)
	}

	cfg := &Config{
		Users: map[string]string{"admin": "password"},
		Services: []ServiceConfig{
			{
				Name:           "test-service",
				WebsiteURL:     "http://localhost:8080",
				ContainerNames: "test-container",
			},
		},
	}

	// Test SaveConfig
	err = SaveConfig(cfg)
	if err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	// Test LoadConfig
	loadedCfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Verify defaults were applied
	if len(loadedCfg.Services) != 1 || !reflect.DeepEqual(loadedCfg.Services[0].AcceptedStatusCodes, []int{200}) {
		t.Errorf("defaults not applied correctly: %+v", loadedCfg.Services[0].AcceptedStatusCodes)
	}

	// Test UpdateConfig
	err = UpdateConfig(func(c *Config) {
		c.Services[0].Name = "updated-service"
	})
	if err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}

	updatedCfg, _ := LoadConfig()
	if updatedCfg.Services[0].Name != "updated-service" {
		t.Errorf("UpdateConfig did not update the name correctly")
	}
}

func TestStatusOperations(t *testing.T) {
	origConfigDir := ConfigDir
	defer func() { ConfigDir = origConfigDir }()

	tmpDir := t.TempDir()
	SetConfigDir(tmpDir)

	// Test LoadStatus on non-existent file
	_, err := LoadStatus()
	if !os.IsNotExist(err) {
		t.Errorf("expected error to be IsNotExist, got %v", err)
	}

	status := &Status{
		Services: []ServiceStatus{
			{
				Name:   "test-service",
				Status: "up",
			},
		},
	}

	// Test SaveStatus
	err = SaveStatus(status)
	if err != nil {
		t.Fatalf("SaveStatus failed: %v", err)
	}

	// Test LoadStatus
	loadedStatus, err := LoadStatus()
	if err != nil {
		t.Fatalf("LoadStatus failed: %v", err)
	}

	if loadedStatus.Services[0].Name != "test-service" {
		t.Errorf("expected service name test-service, got %s", loadedStatus.Services[0].Name)
	}

	// Test UpdateStatus
	err = UpdateStatus(func(s *Status) {
		s.Services[0].Status = "down"
	})
	if err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}

	updatedStatus, _ := LoadStatus()
	if updatedStatus.Services[0].Status != "down" {
		t.Errorf("UpdateStatus did not update the status correctly")
	}
}

func TestUpdateNewFiles(t *testing.T) {
	origConfigDir := ConfigDir
	defer func() { ConfigDir = origConfigDir }()

	tmpDir := t.TempDir()
	SetConfigDir(tmpDir)

	// UpdateConfig on non-existent file should create it
	err := UpdateConfig(func(c *Config) {
		c.Users = map[string]string{"new": "user"}
	})
	if err != nil {
		t.Fatalf("UpdateConfig on new file failed: %v", err)
	}

	cfg, _ := LoadConfig()
	if cfg.Users["new"] != "user" {
		t.Errorf("UpdateConfig on new file did not work")
	}

	// UpdateStatus on non-existent file should create it
	err = UpdateStatus(func(s *Status) {
		s.Services = append(s.Services, ServiceStatus{Name: "new-status"})
	})
	if err != nil {
		t.Fatalf("UpdateStatus on new file failed: %v", err)
	}

	status, _ := LoadStatus()
	if len(status.Services) != 1 || status.Services[0].Name != "new-status" {
		t.Errorf("UpdateStatus on new file did not work")
	}
}

func TestInvalidJSON(t *testing.T) {
	origConfigDir := ConfigDir
	defer func() { ConfigDir = origConfigDir }()

	tmpDir := t.TempDir()
	SetConfigDir(tmpDir)

	// Write invalid JSON to config file
	err := os.WriteFile(filepath.Join(tmpDir, ConfigFile), []byte("{invalid json}"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	_, err = LoadConfig()
	if err == nil {
		t.Error("expected error loading invalid config JSON, got nil")
	}

	err = UpdateConfig(func(c *Config) {})
	if err == nil {
		t.Error("expected error updating invalid config JSON, got nil")
	}

	// Write invalid JSON to status file
	err = os.WriteFile(filepath.Join(tmpDir, StatusFile), []byte("{invalid json}"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	_, err = LoadStatus()
	if err == nil {
		t.Error("expected error loading invalid status JSON, got nil")
	}

	err = UpdateStatus(func(s *Status) {})
	if err == nil {
		t.Error("expected error updating invalid status JSON, got nil")
	}
}
