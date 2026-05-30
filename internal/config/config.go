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

	configCache *Config
	statusCache *Status

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
	Name             string  `json:"name"`
	Status           string  `json:"status"`
	LastFailure      *string `json:"last_failure"`
	DownSince        *string `json:"down_since"`
	UpSince          *string `json:"up_since"`
	LastStableStatus string  `json:"last_stable_status"`
	DownFor          *string `json:"down_for"`
	UpFor            *string `json:"up_for"`
	TimeToRestart    string  `json:"time_to_restart,omitempty"` // populated for the UI
}

func deepCopy(src, dst interface{}) error {
	data, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dst)
}

// LoadConfig reads the configuration file. It creates one with defaults if it doesn't exist.
func LoadConfig() (*Config, error) {
	configMutex.RLock()
	if configCache != nil {
		var cfg Config
		_ = deepCopy(configCache, &cfg)
		configMutex.RUnlock()
		return &cfg, nil
	}
	configMutex.RUnlock()

	configMutex.Lock()
	defer configMutex.Unlock()

	// Double-checked locking
	if configCache != nil {
		var cfg Config
		_ = deepCopy(configCache, &cfg)
		return &cfg, nil
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

	configCache = &cfg

	var res Config
	_ = deepCopy(configCache, &res)
	return &res, nil
}

// SaveConfig writes the configuration file in a thread-safe manner.
func SaveConfig(cfg *Config) error {
	configMutex.Lock()
	defer configMutex.Unlock()

	path := filepath.Join(ConfigDir, ConfigFile)
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}

	// Update cache
	var cached Config
	_ = deepCopy(cfg, &cached)
	configCache = &cached
	return nil
}

// LoadStatus reads the status file.
func LoadStatus() (*Status, error) {
	statusMutex.RLock()
	if statusCache != nil {
		var status Status
		_ = deepCopy(statusCache, &status)
		statusMutex.RUnlock()
		return &status, nil
	}
	statusMutex.RUnlock()

	statusMutex.Lock()
	defer statusMutex.Unlock()

	// Double-checked locking
	if statusCache != nil {
		var status Status
		_ = deepCopy(statusCache, &status)
		return &status, nil
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

	statusCache = &status

	var res Status
	_ = deepCopy(statusCache, &res)
	return &res, nil
}

// SaveStatus writes the status file in a thread-safe manner.
func SaveStatus(status *Status) error {
	statusMutex.Lock()
	defer statusMutex.Unlock()

	path := filepath.Join(ConfigDir, StatusFile)
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}

	data, err := json.MarshalIndent(status, "", "    ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}

	// Update cache
	var cached Status
	_ = deepCopy(status, &cached)
	statusCache = &cached
	return nil
}

// UpdateStatus atomically updates the status using a callback function.
func UpdateStatus(updateFn func(*Status)) error {
	statusMutex.Lock()
	defer statusMutex.Unlock()

	var status Status
	if statusCache != nil {
		_ = deepCopy(statusCache, &status)
	} else {
		path := filepath.Join(ConfigDir, StatusFile)
		// #nosec G304
		data, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return err
			}
			status.Services = []ServiceStatus{}
		} else {
			if err := json.Unmarshal(data, &status); err != nil {
				return err
			}
		}
	}

	updateFn(&status)

	path := filepath.Join(ConfigDir, StatusFile)
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}

	newData, err := json.MarshalIndent(status, "", "    ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, newData, 0600); err != nil {
		return err
	}

	// Update cache
	var cached Status
	_ = deepCopy(&status, &cached)
	statusCache = &cached
	return nil
}

// UpdateConfig atomically updates the configuration using a callback function.
func UpdateConfig(updateFn func(*Config)) error {
	configMutex.Lock()
	defer configMutex.Unlock()

	var cfg Config
	if configCache != nil {
		_ = deepCopy(configCache, &cfg)
	} else {
		path := filepath.Join(ConfigDir, ConfigFile)
		// #nosec G304
		data, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return err
			}
			cfg.Users = make(map[string]string)
			cfg.Services = []ServiceConfig{}
		} else {
			if err := json.Unmarshal(data, &cfg); err != nil {
				return err
			}
		}
	}

	updateFn(&cfg)

	path := filepath.Join(ConfigDir, ConfigFile)
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}

	newData, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, newData, 0600); err != nil {
		return err
	}

	// Update cache
	var cached Config
	_ = deepCopy(&cfg, &cached)
	configCache = &cached
	return nil
}
