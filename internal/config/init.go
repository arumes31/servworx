package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"

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

	// The initial admin password comes from ADMIN_PASSWORD, or is generated
	// randomly and written to InitialPasswordFile. There is no well-known default.
	password, generated, err := initialAdminPassword()
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

	if generated {
		path := filepath.Join(ConfigDir, InitialPasswordFile)
		if err := os.WriteFile(path, []byte(password+"\n"), 0600); err != nil {
			return fmt.Errorf("failed to write initial admin password: %w", err)
		}
		log.Printf("Created initial admin account 'admin'. The generated password is stored in %s (removed after the password is changed)", path)
	} else {
		log.Printf("Created initial admin account from ADMIN_PASSWORD")
	}

	return nil
}

// InitialPasswordFile holds the generated first-run admin password until the
// admin changes it.
const InitialPasswordFile = "initial_admin_password"

// RemoveInitialPasswordFile deletes the generated first-run password file.
func RemoveInitialPasswordFile() {
	_ = os.Remove(filepath.Join(ConfigDir, InitialPasswordFile))
}

// initialAdminPassword returns the password for the first-run admin account and
// whether it was generated randomly.
func initialAdminPassword() (string, bool, error) {
	if p := os.Getenv("ADMIN_PASSWORD"); p != "" {
		if len(p) < 8 {
			return "", false, fmt.Errorf("ADMIN_PASSWORD must be at least 8 characters long")
		}
		return p, false, nil
	}

	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", false, fmt.Errorf("failed to generate initial admin password: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), true, nil
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

func createDefaultConfig(adminPassword string) (*Config, error) {
	adminHash, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
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
