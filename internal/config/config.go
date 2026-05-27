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

	configMutex  sync.RWMutex
	statusMutex  sync.RWMutex
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
	DownSince        *string  `json:"down_since"`
	UpSince          *string  `json:"up_since"`
	LastStableStatus string   `json:"last_stable_status"`
	DownFor          *string  `json:"down_for"`
	UpFor            *string  `json:"up_for"`
	TimeToRestart    string   `json:"time_to_restart,omitempty"` // populated for the UI
}

func (c *Config) DeepCopy() *Config {
	if c == nil {
		return nil
	}
	cp := *c
	if c.Users != nil {
		cp.Users = make(map[string]string, len(c.Users))
		for k, v := range c.Users {
			cp.Users[k] = v
		}
	}
	if c.Services != nil {
		cp.Services = make([]ServiceConfig, len(c.Services))
		for i := range c.Services {
			cp.Services[i] = *c.Services[i].DeepCopy()
		}
	}
	return &cp
}

func (s *ServiceConfig) DeepCopy() *ServiceConfig {
	if s == nil {
		return nil
	}
	cp := *s
	if s.AcceptedStatusCodes != nil {
		cp.AcceptedStatusCodes = make([]int, len(s.AcceptedStatusCodes))
		copy(cp.AcceptedStatusCodes, s.AcceptedStatusCodes)
	}
	return &cp
}

func (s *Status) DeepCopy() *Status {
	if s == nil {
		return nil
	}
	cp := *s
	if s.Services != nil {
		cp.Services = make([]ServiceStatus, len(s.Services))
		for i := range s.Services {
			cp.Services[i] = *s.Services[i].DeepCopy()
		}
	}
	return &cp
}

func (s *ServiceStatus) DeepCopy() *ServiceStatus {
	if s == nil {
		return nil
	}
	cp := *s
	if s.LastFailure != nil {
		val := *s.LastFailure
		cp.LastFailure = &val
	}
	if s.DownSince != nil {
		val := *s.DownSince
		cp.DownSince = &val
	}
	if s.UpSince != nil {
		val := *s.UpSince
		cp.UpSince = &val
	}
	if s.DownFor != nil {
		val := *s.DownFor
		cp.DownFor = &val
	}
	if s.UpFor != nil {
		val := *s.UpFor
		cp.UpFor = &val
	}
	return &cp
}

// LoadConfig reads the configuration file. It creates one with defaults if it doesn't exist.
func LoadConfig() (*Config, error) {
	configMutex.RLock()
	if cachedConfig != nil {
		cfg := cachedConfig.DeepCopy()
		configMutex.RUnlock()
		return cfg, nil
	}
	configMutex.RUnlock()

	configMutex.Lock()
	defer configMutex.Unlock()

	// Double check after acquiring write lock
	if cachedConfig != nil {
		return cachedConfig.DeepCopy(), nil
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
	return cachedConfig.DeepCopy(), nil
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

	cachedConfig = cfg.DeepCopy()
	return nil
}

// LoadStatus reads the status file.
func LoadStatus() (*Status, error) {
	statusMutex.RLock()
	if cachedStatus != nil {
		s := cachedStatus.DeepCopy()
		statusMutex.RUnlock()
		return s, nil
	}
	statusMutex.RUnlock()

	statusMutex.Lock()
	defer statusMutex.Unlock()

	// Double check after acquiring write lock
	if cachedStatus != nil {
		return cachedStatus.DeepCopy(), nil
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
	return cachedStatus.DeepCopy(), nil
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

	cachedStatus = status.DeepCopy()
	return nil
}

// UpdateStatus atomically updates the status using a callback function.
func UpdateStatus(updateFn func(*Status)) error {
	statusMutex.Lock()
	defer statusMutex.Unlock()

	var status *Status
	if cachedStatus != nil {
		status = cachedStatus.DeepCopy()
	} else {
		path := filepath.Join(ConfigDir, StatusFile)
		// #nosec G304
		data, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return err
			}
			status = &Status{Services: []ServiceStatus{}}
		} else {
			status = &Status{}
			if err := json.Unmarshal(data, status); err != nil {
				return err
			}
		}
	}

	updateFn(status)

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

	cachedStatus = status.DeepCopy()
	return nil
}

// UpdateConfig atomically updates the configuration using a callback function.
func UpdateConfig(updateFn func(*Config)) error {
	configMutex.Lock()
	defer configMutex.Unlock()

	var cfg *Config
	if cachedConfig != nil {
		cfg = cachedConfig.DeepCopy()
	} else {
		path := filepath.Join(ConfigDir, ConfigFile)
		// #nosec G304
		data, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return err
			}
			cfg = &Config{
				Users:    make(map[string]string),
				Services: []ServiceConfig{},
			}
		} else {
			cfg = &Config{}
			if err := json.Unmarshal(data, cfg); err != nil {
				return err
			}
		}
	}

	updateFn(cfg)

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

	cachedConfig = cfg.DeepCopy()
	return nil
}

// GetServiceConfig returns the configuration for a single service by name.
func GetServiceConfig(name string) (*ServiceConfig, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return nil, err
	}

	for i := range cfg.Services {
		if cfg.Services[i].Name == name {
			return cfg.Services[i].DeepCopy(), nil
		}
	}

	return nil, fmt.Errorf("service not found: %s", name)
}
