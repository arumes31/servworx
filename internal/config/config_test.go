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
				AcceptedStatusCodes: []int{200}, // explicitly set to match LoadConfig defaults
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

	// Test UpdateConfig
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

	// Test UpdateStatus
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
	clearCache()
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
	clearCache()
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
	clearCache()
	tmpDir := t.TempDir()
	originalDir := ConfigDir
	SetConfigDir(tmpDir)
	t.Cleanup(func() { SetConfigDir(originalDir) })

	cfgJSON := `{
		"users": {},
		"services": [
			{"name": "ServiceWithoutCodes"}
		]
	}`
	if err := os.WriteFile(filepath.Join(tmpDir, ConfigFile), []byte(cfgJSON), 0600); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	loaded, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if len(loaded.Services) != 1 {
		t.Fatalf("Expected 1 service, got %d", len(loaded.Services))
	}

	codes := loaded.Services[0].AcceptedStatusCodes
	if len(codes) != 1 || codes[0] != 200 {
		t.Errorf("Expected default status code [200], got %v", codes)
	}
}

func TestUpdateStatusNewFile(t *testing.T) {
	clearCache()
	tmpDir := t.TempDir()
	originalDir := ConfigDir
	SetConfigDir(tmpDir)
	t.Cleanup(func() { SetConfigDir(originalDir) })

	// Ensure file does not exist
	statusPath := filepath.Join(tmpDir, StatusFile)
	if _, err := os.Stat(statusPath); !os.IsNotExist(err) {
		t.Fatalf("Status file already exists")
	}

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
		t.Errorf("UpdateStatus did not create file correctly, got: %+v", loaded)
	}
}

func TestUpdateConfigNewFile(t *testing.T) {
	clearCache()
	tmpDir := t.TempDir()
	originalDir := ConfigDir
	SetConfigDir(tmpDir)
	t.Cleanup(func() { SetConfigDir(originalDir) })

	// Ensure file does not exist
	configPath := filepath.Join(tmpDir, ConfigFile)
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Fatalf("Config file already exists")
	}

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
		t.Errorf("UpdateConfig did not create file correctly, got: %+v", loaded)
	}
}

func TestUpdateInvalidJSON(t *testing.T) {
	clearCache()
	tmpDir := t.TempDir()
	originalDir := ConfigDir
	SetConfigDir(tmpDir)
	t.Cleanup(func() { SetConfigDir(originalDir) })

	if err := os.WriteFile(filepath.Join(tmpDir, ConfigFile), []byte("invalid json"), 0600); err != nil {
		t.Fatalf("Failed to write invalid config: %v", err)
	}
	err := UpdateConfig(func(cfg *Config) {})
	if err == nil {
		t.Error("Expected error when updating invalid config JSON, got nil")
	}

	if err := os.WriteFile(filepath.Join(tmpDir, StatusFile), []byte("invalid json"), 0600); err != nil {
		t.Fatalf("Failed to write invalid status: %v", err)
	}
	err = UpdateStatus(func(s *Status) {})
	if err == nil {
		t.Error("Expected error when updating invalid status JSON, got nil")
	}
}
func TestConfigCaching(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := ConfigDir
	SetConfigDir(tmpDir)
	clearCache()
	t.Cleanup(func() {
		SetConfigDir(originalDir)
		clearCache()
	})

	cfg := &Config{
		Users: map[string]string{"admin": "hash"},
		Services: []ServiceConfig{
			{
				Name: "Service1",
				AcceptedStatusCodes: []int{200},
			},
		},
	}

	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	// Load should come from cache
	loaded1, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig 1 failed: %v", err)
	}

	// Manually corrupt the file on disk
	path := filepath.Join(tmpDir, ConfigFile)
	if err := os.WriteFile(path, []byte("corrupted json"), 0600); err != nil {
		t.Fatalf("Failed to corrupt config file: %v", err)
	}

	// Load should still succeed because it's cached
	loaded2, err := LoadConfig()
	if err != nil {
		t.Errorf("LoadConfig 2 failed after disk corruption (should have been cached): %v", err)
	}

	if !jsonEqual(loaded1, loaded2) {
		t.Errorf("Cached config changed unexpectedly")
	}

	// UpdateConfig should refresh the cache
	err = UpdateConfig(func(c *Config) {
		c.Services[0].Name = "UpdatedService"
	})
	if err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}

	loaded3, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig 3 failed: %v", err)
	}
	if loaded3.Services[0].Name != "UpdatedService" {
		t.Errorf("Expected UpdatedService, got %s", loaded3.Services[0].Name)
	}
}
