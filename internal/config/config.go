package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

var (
	ConfigDir  = "/app/config"
	ConfigFile = "config.json"
	StatusFile = "status.json"

	configMutex sync.RWMutex
	statusMutex sync.RWMutex

	cachedConfig *Config
	cachedStatus *Status

	// ContainerNameRegex defines valid characters for a Docker container name.
	ContainerNameRegex = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
)

// IsValidContainerName checks if a string is a valid Docker container name.
func IsValidContainerName(name string) bool {
	return ContainerNameRegex.MatchString(name)
}

// SetConfigDir allows overriding the config directory for local testing
func SetConfigDir(dir string) {
	ConfigDir = dir
}

type Config struct {
	Users    map[string]string `json:"users"`
	Services []ServiceConfig   `json:"services"`
}

type ServiceConfig struct {
	Name                string `json:"name"`
	WebsiteURL          string `json:"website_url"`
	ContainerNames      string `json:"container_names"`
	Retries             int    `json:"retries"`
	Interval            int    `json:"interval"`
	GracePeriod         int    `json:"grace_period"`
	AcceptedStatusCodes []int  `json:"accepted_status_codes"`
	Paused              bool   `json:"paused"`
	InsecureSkipVerify  bool   `json:"insecure_skip_verify"`
}

type Status struct {
	Services []ServiceStatus `json:"services"`
}

type ServiceStatus struct {
	Name             string   `json:"name"`
	Status           string   `json:"status"`
	LastFailure      *string  `json:"last_failure"`
	DownSince        *string `json:"down_since"`
	UpSince          *string `json:"up_since"`
	LastStableStatus string  `json:"last_stable_status"`
	DownFor          *string `json:"down_for"`
	UpFor            *string `json:"up_for"`
	TimeToRestart    string  `json:"time_to_restart,omitempty"` // populated for the UI
}

// LoadConfig reads the configuration file. It creates one with defaults if it doesn't exist.
func LoadConfig() (*Config, error) {
	configMutex.RLock()
	if cachedConfig != nil {
		defer configMutex.RUnlock()
		return copyConfig(cachedConfig), nil
	}
	configMutex.RUnlock()

	configMutex.Lock()
	defer configMutex.Unlock()

	// Double-checked locking
	if cachedConfig != nil {
		return copyConfig(cachedConfig), nil
	}

	path := filepath.Join(ConfigDir, ConfigFile)
	// #nosec G304
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, err // Handled by initialization
		}
		return nil, fmt.Errorf("failed to read config: %v", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config json: %v", err)
	}

	// Ensure defaults
	for i := range cfg.Services {
		if cfg.Services[i].AcceptedStatusCodes == nil {
			cfg.Services[i].AcceptedStatusCodes = []int{200}
		}
	}

	cachedConfig = &cfg
	return copyConfig(cachedConfig), nil
}

// SaveConfig writes the configuration file in a thread-safe manner.
func SaveConfig(cfg *Config) error {
	configMutex.Lock()
	defer configMutex.Unlock()

	cachedConfig = copyConfig(cfg)

	path := filepath.Join(ConfigDir, ConfigFile)
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cachedConfig, "", "    ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// LoadStatus reads the status file.
func LoadStatus() (*Status, error) {
	statusMutex.RLock()
	if cachedStatus != nil {
		defer statusMutex.RUnlock()
		return copyStatus(cachedStatus), nil
	}
	statusMutex.RUnlock()

	statusMutex.Lock()
	defer statusMutex.Unlock()

	// Double-checked locking
	if cachedStatus != nil {
		return copyStatus(cachedStatus), nil
	}

	path := filepath.Join(ConfigDir, StatusFile)
	// #nosec G304
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to read status: %v", err)
	}

	var status Status
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, fmt.Errorf("failed to parse status json: %v", err)
	}

	cachedStatus = &status
	return copyStatus(cachedStatus), nil
}

// SaveStatus writes the status file in a thread-safe manner.
func SaveStatus(status *Status) error {
	statusMutex.Lock()
	defer statusMutex.Unlock()

	cachedStatus = copyStatus(status)

	path := filepath.Join(ConfigDir, StatusFile)
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cachedStatus, "", "    ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// UpdateStatus atomically updates the status using a callback function.
func UpdateStatus(updateFn func(*Status)) error {
	statusMutex.Lock()
	defer statusMutex.Unlock()

	if cachedStatus == nil {
		path := filepath.Join(ConfigDir, StatusFile)
		// #nosec G304
		data, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return err
			}
			cachedStatus = &Status{
				Services: []ServiceStatus{},
			}
		} else {
			var status Status
			if err := json.Unmarshal(data, &status); err != nil {
				return err
			}
			cachedStatus = &status
		}
	}

	updateFn(cachedStatus)

	path := filepath.Join(ConfigDir, StatusFile)
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}

	newData, err := json.MarshalIndent(cachedStatus, "", "    ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, newData, 0600)
}

// UpdateConfig atomically updates the configuration using a callback function.
func UpdateConfig(updateFn func(*Config)) error {
	configMutex.Lock()
	defer configMutex.Unlock()

	if cachedConfig == nil {
		path := filepath.Join(ConfigDir, ConfigFile)
		// #nosec G304
		data, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return err
			}
			cachedConfig = &Config{
				Users:    make(map[string]string),
				Services: []ServiceConfig{},
			}
		} else {
			var cfg Config
			if err := json.Unmarshal(data, &cfg); err != nil {
				return err
			}
			cachedConfig = &cfg
		}
	}

	updateFn(cachedConfig)

	path := filepath.Join(ConfigDir, ConfigFile)
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}

	newData, err := json.MarshalIndent(cachedConfig, "", "    ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, newData, 0600)
}

// copyConfig creates a deep copy of the Config struct using JSON marshaling.
func copyConfig(c *Config) *Config {
	if c == nil {
		return nil
	}
	data, _ := json.Marshal(c)
	var cp Config
	_ = json.Unmarshal(data, &cp)
	return &cp
}

// copyStatus creates a deep copy of the Status struct using JSON marshaling.
func copyStatus(s *Status) *Status {
	if s == nil {
		return nil
	}
	data, _ := json.Marshal(s)
	var cp Status
	_ = json.Unmarshal(data, &cp)
	return &cp
}
