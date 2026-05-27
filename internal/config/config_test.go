package config

import (
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
		t.Errorf("SetConfigDir(%q) failed, ConfigDir = %q", newDir, ConfigDir)
	}
}

func TestConfigPersistence(t *testing.T) {
	oldDir := ConfigDir
	t.Cleanup(func() {
		ConfigDir = oldDir
	})

	tempDir := t.TempDir()
	SetConfigDir(tempDir)

	// Test LoadConfig when file doesn't exist
	cfg, err := LoadConfig()
	if err == nil {
		t.Error("LoadConfig() should return error when file doesn't exist")
	}
	if cfg != nil {
		t.Error("LoadConfig() should return nil config when file doesn't exist")
	}

	// Test SaveConfig
	initialCfg := &Config{
		Users: map[string]string{"admin": "password"},
		Services: []ServiceConfig{
			{
				Name:           "service1",
				WebsiteURL:     "http://localhost:8080",
				ContainerNames: "cont1,cont2",
			},
		},
	}

	err = SaveConfig(initialCfg)
	if err != nil {
		t.Fatalf("SaveConfig() failed: %v", err)
	}

	// Test LoadConfig
	loadedCfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() failed: %v", err)
	}

	// Verify defaults were applied (AcceptedStatusCodes)
	if len(loadedCfg.Services) > 0 {
		if !reflect.DeepEqual(loadedCfg.Services[0].AcceptedStatusCodes, []int{200}) {
			t.Errorf("Expected default AcceptedStatusCodes [200], got %v", loadedCfg.Services[0].AcceptedStatusCodes)
		}
	}

	// For comparison, we need to set the expected defaults in initialCfg
	initialCfg.Services[0].AcceptedStatusCodes = []int{200}
	if !reflect.DeepEqual(initialCfg, loadedCfg) {
		t.Errorf("Loaded config does not match saved config.\nSaved: %+v\nLoaded: %+v", initialCfg, loadedCfg)
	}
}

func TestStatusPersistence(t *testing.T) {
	oldDir := ConfigDir
	t.Cleanup(func() {
		ConfigDir = oldDir
	})

	tempDir := t.TempDir()
	SetConfigDir(tempDir)

	// Test LoadStatus when file doesn't exist
	status, err := LoadStatus()
	if err == nil {
		t.Error("LoadStatus() should return error when file doesn't exist")
	}
	if status != nil {
		t.Error("LoadStatus() should return nil status when file doesn't exist")
	}

	// Test SaveStatus
	initialStatus := &Status{
		Services: []ServiceStatus{
			{
				Name:   "service1",
				Status: "up",
			},
		},
	}

	err = SaveStatus(initialStatus)
	if err != nil {
		t.Fatalf("SaveStatus() failed: %v", err)
	}

	// Test LoadStatus
	loadedStatus, err := LoadStatus()
	if err != nil {
		t.Fatalf("LoadStatus() failed: %v", err)
	}

	if !reflect.DeepEqual(initialStatus, loadedStatus) {
		t.Errorf("Loaded status does not match saved status.\nSaved: %+v\nLoaded: %+v", initialStatus, loadedStatus)
	}
}

func TestUpdateConfig(t *testing.T) {
	oldDir := ConfigDir
	t.Cleanup(func() {
		ConfigDir = oldDir
	})

	tempDir := t.TempDir()
	SetConfigDir(tempDir)

	// Test UpdateConfig when file doesn't exist
	err := UpdateConfig(func(cfg *Config) {
		if cfg.Users == nil {
			cfg.Users = make(map[string]string)
		}
		cfg.Users["newuser"] = "newpass"
		cfg.Services = append(cfg.Services, ServiceConfig{Name: "newservice"})
	})
	if err != nil {
		t.Fatalf("UpdateConfig() failed on non-existent file: %v", err)
	}

	loadedCfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() failed: %v", err)
	}

	if loadedCfg.Users["newuser"] != "newpass" || len(loadedCfg.Services) != 1 || loadedCfg.Services[0].Name != "newservice" {
		t.Errorf("UpdateConfig() did not correctly initialize or update config: %+v", loadedCfg)
	}

	// Test UpdateConfig on existing file
	err = UpdateConfig(func(cfg *Config) {
		cfg.Users["anotheruser"] = "anotherpass"
	})
	if err != nil {
		t.Fatalf("UpdateConfig() failed on existing file: %v", err)
	}

	loadedCfg, err = LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() failed: %v", err)
	}
	if loadedCfg.Users["anotheruser"] != "anotherpass" || loadedCfg.Users["newuser"] != "newpass" {
		t.Errorf("UpdateConfig() did not correctly update existing config: %+v", loadedCfg)
	}
}

func TestUpdateStatus(t *testing.T) {
	oldDir := ConfigDir
	t.Cleanup(func() {
		ConfigDir = oldDir
	})

	tempDir := t.TempDir()
	SetConfigDir(tempDir)

	// Test UpdateStatus when file doesn't exist
	err := UpdateStatus(func(s *Status) {
		s.Services = append(s.Services, ServiceStatus{Name: "svc1", Status: "down"})
	})
	if err != nil {
		t.Fatalf("UpdateStatus() failed on non-existent file: %v", err)
	}

	loadedStatus, err := LoadStatus()
	if err != nil {
		t.Fatalf("LoadStatus() failed: %v", err)
	}

	if len(loadedStatus.Services) != 1 || loadedStatus.Services[0].Name != "svc1" {
		t.Errorf("UpdateStatus() did not correctly initialize or update status: %+v", loadedStatus)
	}

	// Test UpdateStatus on existing file
	err = UpdateStatus(func(s *Status) {
		s.Services[0].Status = "up"
	})
	if err != nil {
		t.Fatalf("UpdateStatus() failed on existing file: %v", err)
	}

	loadedStatus, err = LoadStatus()
	if err != nil {
		t.Fatalf("LoadStatus() failed: %v", err)
	}
	if loadedStatus.Services[0].Status != "up" {
		t.Errorf("UpdateStatus() did not correctly update existing status: %+v", loadedStatus)
	}
}
