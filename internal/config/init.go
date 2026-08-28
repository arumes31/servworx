package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// InitDefaultFiles initializes the configuration and status files if they don't exist.
func InitDefaultFiles() error {
	if err := os.MkdirAll(ConfigDir, 0750); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	if err := initConfig(); err != nil {
		return err
	}

	if err := initStatus(); err != nil {
		return err
	}

	return nil
}

func initConfig() error {
	cfg, err := LoadConfig()
	if err == nil {
		adminHash, ok := cfg.Users["admin"]
		if !ok || adminHash == "" {
			return errors.New("existing configuration has no administrator credential")
		}
		if bcrypt.CompareHashAndPassword([]byte(adminHash), []byte("changeme")) == nil {
			password, err := loadBootstrapPassword()
			if err != nil {
				return fmt.Errorf("legacy default administrator credential must be rotated: %w", err)
			}
			hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if err != nil {
				return fmt.Errorf("hash replacement administrator password: %w", err)
			}
			cfg.Users["admin"] = string(hash)
			if err := SaveConfig(cfg); err != nil {
				return fmt.Errorf("save rotated administrator credential: %w", err)
			}
		}
		return nil
	}

	if !os.IsNotExist(err) {
		return fmt.Errorf("failed to load config: %w", err)
	}

	password, err := loadBootstrapPassword()
	if err != nil {
		return err
	}
	defaultCfg, err := createDefaultConfig(password)
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

func createDefaultConfig(password string) (*Config, error) {
	adminHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
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

func loadBootstrapPassword() (string, error) {
	password := os.Getenv("SERVWORX_ADMIN_PASSWORD")
	if filename := os.Getenv("SERVWORX_ADMIN_PASSWORD_FILE"); filename != "" {
		// #nosec G304 G703 -- startup-only path supplied by the deployment operator, never by an HTTP request.
		data, err := os.ReadFile(filename)
		if err != nil {
			return "", fmt.Errorf("read administrator password file: %w", err)
		}
		password = strings.TrimSpace(string(data))
	}
	if len(password) < 16 {
		return "", errors.New("SERVWORX_ADMIN_PASSWORD or SERVWORX_ADMIN_PASSWORD_FILE is required and must contain at least 16 characters")
	}
	if strings.TrimSpace(password) != password || password == "changeme" {
		return "", errors.New("administrator password must not have surrounding whitespace or use the legacy default")
	}
	return password, nil
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
