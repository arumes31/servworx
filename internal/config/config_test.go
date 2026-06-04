package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func jsonEqual(a, b interface{}) bool {
	aBytes, _ := json.Marshal(a)
	bBytes, _ := json.Marshal(b)
	return string(aBytes) == string(bBytes)
}

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

func TestConfigPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := ConfigDir
	SetConfigDir(tmpDir)
	t.Cleanup(func() { SetConfigDir(originalDir) })

	cfg := &Config{
		Users: map[string]string{"admin": "hash"},
		Services: []ServiceConfig{
			{
				Name:                "Service1",
				WebsiteURL:          "http://localhost:8080",
				AcceptedStatusCodes: []int{200},
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

	if !jsonEqual(cfg, loaded) {
		t.Errorf("Loaded config does not match saved config\nSaved: %+v\nLoaded: %+v", cfg, loaded)
	}
}

func TestStatusPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := ConfigDir
	SetConfigDir(tmpDir)
	t.Cleanup(func() { SetConfigDir(originalDir) })

	status := &Status{
		Services: []ServiceStatus{
			{Name: "Service1", Status: "Up"},
		},
	}

	if err := SaveStatus(status); err != nil {
		t.Fatalf("SaveStatus failed: %v", err)
	}

	loaded, err := LoadStatus()
	if err != nil {
		t.Fatalf("LoadStatus failed: %v", err)
	}

	if !jsonEqual(status, loaded) {
		t.Errorf("Loaded status does not match saved status\nSaved: %+v\nLoaded: %+v", status, loaded)
	}
}

func TestAtomicUpdates(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := ConfigDir
	SetConfigDir(tmpDir)
	t.Cleanup(func() { SetConfigDir(originalDir) })

	err := UpdateConfig(func(cfg *Config) {
		cfg.Users["testuser"] = "testpass"
	})
	if err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}

	loadedCfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if loadedCfg.Users["testuser"] != "testpass" {
		t.Errorf("UpdateConfig did not persist change")
	}

	err = UpdateStatus(func(s *Status) {
		s.Services = append(s.Services, ServiceStatus{Name: "NewService", Status: "Down"})
	})
	if err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}

	loadedStatus, err := LoadStatus()
	if err != nil {
		t.Fatalf("LoadStatus failed: %v", err)
	}
	found := false
	for _, s := range loadedStatus.Services {
		if s.Name == "NewService" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("UpdateStatus did not persist change")
	}
}

func TestLoadNonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := ConfigDir
	SetConfigDir(tmpDir)
	t.Cleanup(func() { SetConfigDir(originalDir) })

	_, err := LoadConfig()
	if err == nil || !os.IsNotExist(err) {
		t.Errorf("Expected NotExist error for non-existent config, got: %v", err)
	}

	_, err = LoadStatus()
	if err == nil || !os.IsNotExist(err) {
		t.Errorf("Expected NotExist error for non-existent status, got: %v", err)
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := ConfigDir
	SetConfigDir(tmpDir)
	t.Cleanup(func() { SetConfigDir(originalDir) })

	if err := os.WriteFile(filepath.Join(tmpDir, ConfigFile), []byte("invalid json"), 0600); err != nil {
		t.Fatalf("Failed to write invalid config: %v", err)
	}
	_, err := LoadConfig()
	if err == nil {
		t.Error("Expected error when loading invalid config JSON, got nil")
	}

	if err := os.WriteFile(filepath.Join(tmpDir, StatusFile), []byte("invalid json"), 0600); err != nil {
		t.Fatalf("Failed to write invalid status: %v", err)
	}
	_, err = LoadStatus()
	if err == nil {
		t.Error("Expected error when loading invalid status JSON, got nil")
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := ConfigDir
	SetConfigDir(tmpDir)
	t.Cleanup(func() { SetConfigDir(originalDir) })

	cfgJSON := `{"users": {}, "services": [{"name": "ServiceWithoutCodes"}]}`
	if err := os.WriteFile(filepath.Join(tmpDir, ConfigFile), []byte(cfgJSON), 0600); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	loaded, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if len(loaded.Services) != 1 || len(loaded.Services[0].AcceptedStatusCodes) != 1 || loaded.Services[0].AcceptedStatusCodes[0] != 200 {
		t.Errorf("Expected default status code [200], got %v", loaded.Services[0].AcceptedStatusCodes)
	}
}

func TestUpdateStatusNewFile(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := ConfigDir
	SetConfigDir(tmpDir)
	t.Cleanup(func() { SetConfigDir(originalDir) })

	err := UpdateStatus(func(s *Status) {
		s.Services = append(s.Services, ServiceStatus{Name: "InitialService", Status: "Up"})
	})
	if err != nil {
		t.Fatalf("UpdateStatus failed on new file: %v", err)
	}

	loaded, err := LoadStatus()
	if err != nil {
		t.Fatalf("LoadStatus failed: %v", err)
	}
	if len(loaded.Services) != 1 || loaded.Services[0].Name != "InitialService" {
		t.Errorf("UpdateStatus did not create file correctly")
	}
}

func TestUpdateConfigNewFile(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := ConfigDir
	SetConfigDir(tmpDir)
	t.Cleanup(func() { SetConfigDir(originalDir) })

	err := UpdateConfig(func(cfg *Config) {
		cfg.Users["newadmin"] = "newhash"
	})
	if err != nil {
		t.Fatalf("UpdateConfig failed on new file: %v", err)
	}

	loaded, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if loaded.Users["newadmin"] != "newhash" {
		t.Errorf("UpdateConfig did not create file correctly")
	}
}

func TestUpdateInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := ConfigDir
	SetConfigDir(tmpDir)
	t.Cleanup(func() { SetConfigDir(originalDir) })

	os.WriteFile(filepath.Join(tmpDir, ConfigFile), []byte("invalid json"), 0600)
	if err := UpdateConfig(func(cfg *Config) {}); err == nil {
		t.Error("Expected error when updating invalid config JSON")
	}

	os.WriteFile(filepath.Join(tmpDir, StatusFile), []byte("invalid json"), 0600)
	if err := UpdateStatus(func(s *Status) {}); err == nil {
		t.Error("Expected error when updating invalid status JSON")
	}
}

func TestServiceConfig_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		expected ServiceConfig
	}{
		{
			name: "defaults",
			json: `{"name": "test"}`,
			expected: ServiceConfig{Name: "test", AlertOnFailure: true, AlertOnRecovery: true, AlertOnRestart: true},
		},
		{
			name: "explicit false",
			json: `{"name": "test", "alert_on_failure": false, "alert_on_recovery": false, "alert_on_restart": false}`,
			expected: ServiceConfig{Name: "test", AlertOnFailure: false, AlertOnRecovery: false, AlertOnRestart: false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got ServiceConfig
			if err := json.Unmarshal([]byte(tt.json), &got); err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}
			if got.AlertOnFailure != tt.expected.AlertOnFailure || got.AlertOnRecovery != tt.expected.AlertOnRecovery || got.AlertOnRestart != tt.expected.AlertOnRestart {
				t.Errorf("UnmarshalJSON mismatch")
			}
		})
	}
}

func TestServiceConfig_UnmarshalJSON_Error(t *testing.T) {
	var s ServiceConfig
	if err := s.UnmarshalJSON([]byte(`{invalid}`)); err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

func TestSaveErrors(t *testing.T) {
	tmpDir := t.TempDir()
	badDir := filepath.Join(tmpDir, "readonly")
	os.MkdirAll(badDir, 0500)
	originalDir := ConfigDir
	SetConfigDir(badDir)
	t.Cleanup(func() { SetConfigDir(originalDir) })

	if err := SaveConfig(&Config{}); err == nil {
		t.Error("Expected error in SaveConfig")
	}
	if err := SaveStatus(&Status{}); err == nil {
		t.Error("Expected error in SaveStatus")
	}
}

func TestUpdateErrors(t *testing.T) {
	tmpDir := t.TempDir()
	badDir := filepath.Join(tmpDir, "readonly")
	os.MkdirAll(badDir, 0500)
	originalDir := ConfigDir
	SetConfigDir(badDir)
	t.Cleanup(func() { SetConfigDir(originalDir) })

	if err := UpdateConfig(func(c *Config) {}); err == nil {
		t.Error("Expected error in UpdateConfig")
	}
	if err := UpdateStatus(func(s *Status) {}); err == nil {
		t.Error("Expected error in UpdateStatus")
	}
}

func TestSaveMkdirError(t *testing.T) {
	tmpDir := t.TempDir()
	blockedDir := filepath.Join(tmpDir, "blocked")
	os.WriteFile(blockedDir, []byte("file"), 0600)
	originalDir := ConfigDir
	SetConfigDir(filepath.Join(blockedDir, "config"))
	t.Cleanup(func() { SetConfigDir(originalDir) })

	if err := SaveConfig(&Config{}); err == nil {
		t.Error("Expected error in SaveConfig Mkdir")
	}
	if err := SaveStatus(&Status{}); err == nil {
		t.Error("Expected error in SaveStatus Mkdir")
	}
}

func TestUpdateReadFileError(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := ConfigDir
	SetConfigDir(tmpDir)
	t.Cleanup(func() { SetConfigDir(originalDir) })

	os.MkdirAll(filepath.Join(tmpDir, ConfigFile), 0750)
	if err := UpdateConfig(func(c *Config) {}); err == nil {
		t.Error("Expected error in UpdateConfig ReadFile")
	}

	os.MkdirAll(filepath.Join(tmpDir, StatusFile), 0750)
	if err := UpdateStatus(func(s *Status) {}); err == nil {
		t.Error("Expected error in UpdateStatus ReadFile")
	}
}

func TestUpdateMkdirError(t *testing.T) {
	tmpDir := t.TempDir()
	blockedDir := filepath.Join(tmpDir, "blocked")
	os.WriteFile(blockedDir, []byte("file"), 0600)
	originalDir := ConfigDir
	SetConfigDir(filepath.Join(blockedDir, "config"))
	t.Cleanup(func() { SetConfigDir(originalDir) })

	if err := UpdateConfig(func(c *Config) {}); err == nil {
		t.Error("Expected error in UpdateConfig Mkdir")
	}
	if err := UpdateStatus(func(s *Status) {}); err == nil {
		t.Error("Expected error in UpdateStatus Mkdir")
	}
}
