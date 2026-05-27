package config

import (
	"os"
	"testing"
)

func TestCacheEfficiency(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "servworx_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	origDir := ConfigDir
	ConfigDir = tmpDir
	defer func() { ConfigDir = origDir }()

	// Reset cache
	cachedConfig = nil
	cachedStatus = nil

	// Initial save
	cfg := &Config{
		Users: map[string]string{"test": "pass"},
		Services: []ServiceConfig{
			{Name: "test-svc", WebsiteURL: "http://example.com"},
		},
	}
	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	// First load (should hit disk and populate cache)
	loaded1, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig 1 failed: %v", err)
	}
	if loaded1.Users["test"] != "pass" {
		t.Errorf("Expected user test to be pass, got %s", loaded1.Users["test"])
	}

	// Modify the loaded config and check if it affects the cache (should not)
	loaded1.Users["test"] = "hacked"

	loaded2, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig 2 failed: %v", err)
	}
	if loaded2.Users["test"] != "pass" {
		t.Errorf("Cache was mutated! Expected pass, got %s", loaded2.Users["test"])
	}

	// Check GetServiceConfig
	svc, err := GetServiceConfig("test-svc")
	if err != nil {
		t.Fatalf("GetServiceConfig failed: %v", err)
	}
	if svc.Name != "test-svc" {
		t.Errorf("Expected test-svc, got %s", svc.Name)
	}

	// Check status cache
	status := &Status{
		Services: []ServiceStatus{
			{Name: "test-svc", Status: "Up"},
		},
	}
	if err := SaveStatus(status); err != nil {
		t.Fatalf("SaveStatus failed: %v", err)
	}

	err = UpdateStatus(func(s *Status) {
		s.Services[0].Status = "Down"
	})
	if err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}

	loadedStatus, err := LoadStatus()
	if err != nil {
		t.Fatalf("LoadStatus failed: %v", err)
	}
	if loadedStatus.Services[0].Status != "Down" {
		t.Errorf("Expected Down, got %s", loadedStatus.Services[0].Status)
	}
}
