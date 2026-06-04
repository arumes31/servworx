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

	// ContainerNameRegex defines valid characters for a Docker container name.
	ContainerNameRegex = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

	cachedConfig *Config
	cachedStatus *Status
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
	EnableWebhook       bool   `json:"enable_webhook"`
	EnableTeams         bool   `json:"enable_teams"`
	EnableTelegram      bool   `json:"enable_telegram"`
	EnableEmail         bool   `json:"enable_email"`
	AlertOnFailure      bool   `json:"alert_on_failure"`
	AlertOnRecovery     bool   `json:"alert_on_recovery"`
	AlertOnRestart      bool   `json:"alert_on_restart"`
	AlertRepeatInterval int    `json:"alert_repeat_interval"`
	AlertMaxRepeats     int    `json:"alert_max_repeats"`
	EnableDiscord       bool   `json:"enable_discord"`
	EnableGotify        bool   `json:"enable_gotify"`
	EnablePushover      bool   `json:"enable_pushover"`
	QuietHoursStart     string `json:"quiet_hours_start"`
	QuietHoursEnd       string `json:"quiet_hours_end"`
	AlertSnoozeUntil    int64  `json:"alert_snooze_until"`
}

// UnmarshalJSON implements a custom JSON unmarshaller to ensure new boolean settings default to true for backward compatibility.
func (s *ServiceConfig) UnmarshalJSON(data []byte) error {
	type Alias ServiceConfig
	aux := &struct {
		AlertOnFailure  *bool `json:"alert_on_failure"`
		AlertOnRecovery *bool `json:"alert_on_recovery"`
		AlertOnRestart  *bool `json:"alert_on_restart"`
		*Alias
	}{
		Alias: (*Alias)(s),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.AlertOnFailure == nil {
		s.AlertOnFailure = true
	} else {
		s.AlertOnFailure = *aux.AlertOnFailure
	}
	if aux.AlertOnRecovery == nil {
		s.AlertOnRecovery = true
	} else {
		s.AlertOnRecovery = *aux.AlertOnRecovery
	}
	if aux.AlertOnRestart == nil {
		s.AlertOnRestart = true
	} else {
		s.AlertOnRestart = *aux.AlertOnRestart
	}
	return nil
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
	LastAlertTime    *int64  `json:"last_alert_time,omitempty"`
	AlertCount       int     `json:"alert_count"`
}

// deepCopy creates a deep copy of the source object using JSON marshaling.
func deepCopy(src, dst interface{}) error {
	data, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dst)
}

func ClearCache() {
	configMutex.Lock()
	cachedConfig = nil
	configMutex.Unlock()

	statusMutex.Lock()
	cachedStatus = nil
	statusMutex.Unlock()
}

// LoadConfig reads the configuration file. It creates one with defaults if it doesn't exist.
func LoadConfig() (*Config, error) {
	configMutex.RLock()
	if cachedConfig != nil {
		var cfg Config
		err := deepCopy(cachedConfig, &cfg)
		configMutex.RUnlock()
		return &cfg, err
	}
	configMutex.RUnlock()

	configMutex.Lock()
	defer configMutex.Unlock()

	if cachedConfig != nil {
		var cfg Config
		err := deepCopy(cachedConfig, &cfg)
		return &cfg, err
	}

	path := filepath.Join(ConfigDir, ConfigFile)
	// #nosec G304
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config json: %v", err)
	}

	for i := range cfg.Services {
		if cfg.Services[i].AcceptedStatusCodes == nil {
			cfg.Services[i].AcceptedStatusCodes = []int{200}
		}
	}

	cachedConfig = &cfg
	var result Config
	err = deepCopy(cachedConfig, &result)
	return &result, err
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

	var cached Config
	if err := deepCopy(cfg, &cached); err != nil {
		return err
	}
	cachedConfig = &cached
	return nil
}

// LoadStatus reads the status file.
func LoadStatus() (*Status, error) {
	statusMutex.RLock()
	if cachedStatus != nil {
		var status Status
		err := deepCopy(cachedStatus, &status)
		statusMutex.RUnlock()
		return &status, err
	}
	statusMutex.RUnlock()

	statusMutex.Lock()
	defer statusMutex.Unlock()

	if cachedStatus != nil {
		var status Status
		err := deepCopy(cachedStatus, &status)
		return &status, err
	}

	path := filepath.Join(ConfigDir, StatusFile)
	// #nosec G304
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var status Status
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, fmt.Errorf("failed to parse status json: %v", err)
	}

	cachedStatus = &status
	var result Status
	err = deepCopy(cachedStatus, &result)
	return &result, err
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

	var cached Status
	if err := deepCopy(status, &cached); err != nil {
		return err
	}
	cachedStatus = &cached
	return nil
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

	var status Status
	if err := deepCopy(cachedStatus, &status); err != nil {
		return err
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

	cachedStatus = &status
	return nil
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

	var cfg Config
	if err := deepCopy(cachedConfig, &cfg); err != nil {
		return err
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

	cachedConfig = &cfg
	return nil
}
