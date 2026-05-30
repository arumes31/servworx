package config

import (
	"os"
	"testing"
)

func TestConfigCaching(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "config_cache_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldDir := ConfigDir
	ConfigDir = tmpDir
	defer func() { ConfigDir = oldDir }()

	// Reset cache
	configCache = nil

	// 1. Initial save
	cfg := &Config{
		Users: map[string]string{"admin": "hash"},
		Services: []ServiceConfig{
			{Name: "S1", WebsiteURL: "http://s1.com"},
		},
	}
	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	if configCache == nil {
		t.Fatal("configCache should not be nil after SaveConfig")
	}

	// 2. Load should come from cache
	loaded, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if loaded.Services[0].Name != "S1" {
		t.Errorf("expected S1, got %s", loaded.Services[0].Name)
	}

	// 3. UpdateConfig should update cache
	err = UpdateConfig(func(c *Config) {
		c.Services[0].Name = "S1-Updated"
	})
	if err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}

	if configCache.Services[0].Name != "S1-Updated" {
		t.Errorf("configCache not updated, got %s", configCache.Services[0].Name)
	}

	loaded2, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if loaded2.Services[0].Name != "S1-Updated" {
		t.Errorf("LoadConfig did not return updated name, got %s", loaded2.Services[0].Name)
	}

	// 4. Verify deep copy
	loaded2.Services[0].Name = "Hacked"
	if configCache.Services[0].Name == "Hacked" {
		t.Error("configCache was modified by changing loaded config (not a deep copy)")
	}
}

func TestStatusCaching(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "status_cache_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldDir := ConfigDir
	ConfigDir = tmpDir
	defer func() { ConfigDir = oldDir }()

	// Reset cache
	statusCache = nil

	// 1. Initial save
	status := &Status{
		Services: []ServiceStatus{
			{Name: "S1", Status: "Up"},
		},
	}
	if err := SaveStatus(status); err != nil {
		t.Fatalf("SaveStatus failed: %v", err)
	}

	if statusCache == nil {
		t.Fatal("statusCache should not be nil after SaveStatus")
	}

	// 2. Load status
	loaded, err := LoadStatus()
	if err != nil {
		t.Fatalf("LoadStatus failed: %v", err)
	}
	if loaded.Services[0].Status != "Up" {
		t.Errorf("expected Up, got %s", loaded.Services[0].Status)
	}

	// 3. UpdateStatus
	err = UpdateStatus(func(s *Status) {
		s.Services[0].Status = "Down"
	})
	if err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}

	if statusCache.Services[0].Status != "Down" {
		t.Errorf("statusCache not updated, got %s", statusCache.Services[0].Status)
	}

	// 4. Verify deep copy
	loaded.Services[0].Status = "Unknown"
	if statusCache.Services[0].Status == "Unknown" {
		t.Error("statusCache was modified by changing loaded status (not a deep copy)")
	}
}
