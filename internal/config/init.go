package config

import (
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

// InitDefaultFiles initializes the configuration and status files if they don't exist.
func InitDefaultFiles() error {
	_ = os.MkdirAll(ConfigDir, 0750)

	if err := initConfig(); err != nil {
		return err
	}

	if err := initStatus(); err != nil {
		return err
	}

	return nil
}

func initConfig() error {
	_, err := LoadConfig()
	if err == nil {
		return nil
	}

	if !os.IsNotExist(err) {
		return fmt.Errorf("failed to load config: %w", err)
	}

	defaultCfg, err := createDefaultConfig()
	if err != nil {
		return err
	}

	if err := SaveConfig(defaultCfg); err != nil {
		return fmt.Errorf("failed to save default config: %w", err)
	}

	return nil
}

func initStatus() error {
	_, err := LoadStatus()
	if err == nil {
		return nil
	}

	if !os.IsNotExist(err) {
		return fmt.Errorf("failed to load status: %w", err)
	}

	defaultStatus := createDefaultStatus()
	if err := SaveStatus(defaultStatus); err != nil {
		return fmt.Errorf("failed to save default status: %w", err)
	}

	return nil
}

func createDefaultConfig() (*Config, error) {
	adminHash, err := bcrypt.GenerateFromPassword([]byte("changeme"), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash default password: %w", err)
	}

	return &Config{
		Users: map[string]string{"admin": string(adminHash)},
		Services: []ServiceConfig{
			{
				Name:                "Service1",
				WebsiteURL:          "http://example.com",
				ContainerNames:      "service1",
				Retries:             15,
				Interval:            120,
				GracePeriod:         3600,
				AcceptedStatusCodes: []int{200},
				Paused:              false,
			},
		},
	}, nil
}

func createDefaultStatus() *Status {
	return &Status{
		Services: []ServiceStatus{
			{
				Name:             "Service1",
				Status:           "Unknown",
				LastStableStatus: "Unknown",
			},
		},
	}
}
