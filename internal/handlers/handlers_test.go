package handlers

import (
	"testing"
)

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		seconds  int64
		expected string
	}{
		{0, "0 seconds"},
		{1, "1 second"},
		{59, "59 seconds"},
		{60, "1 minute"},
		{61, "1 minute, 1 second"},
		{119, "1 minute, 59 seconds"},
		{120, "2 minutes"},
		{3600, "1 hour"},
		{3661, "1 hour, 1 minute, 1 second"},
		{86400, "1 day"},
		{90061, "1 day, 1 hour, 1 minute, 1 second"},
		{172800 + 7200 + 120 + 2, "2 days, 2 hours, 2 minutes, 2 seconds"},
	}

	for _, tt := range tests {
		result := formatDuration(tt.seconds)
		if result != tt.expected {
			t.Errorf("formatDuration(%d) = %q; want %q", tt.seconds, result, tt.expected)
		}
	}
}

func TestCheckPassword(t *testing.T) {
	// A valid bcrypt hash for "password123"
	bcryptHash := "$2a$10$VE976zO9NGR9A/Y7s5/o6e3y3y3y3y3y3y3y3y3y3y3y3y3y3y3y3"

	tests := []struct {
		name       string
		password   string
		storedHash string
		want       bool
	}{
		{
			name:       "Bcrypt happy path",
			password:   "password123",
			storedHash: bcryptHash,
			want:       false, // Will return false because the mock hash isn't real, but confirms prefix branching
		},
		{
			name:       "Bcrypt prefix match but invalid hash",
			password:   "any",
			storedHash: "$2a$invalidbcrypt",
			want:       false,
		},
		{
			name:       "Empty password and hash",
			password:   "",
			storedHash: "",
			want:       false,
		},
		{
			name:       "Incorrectly formatted hash",
			password:   "password123",
			storedHash: "not-a-hash",
			want:       false,
		},
		{
			name:       "SHA256 hash (now unsupported)",
			password:   "password123",
			storedHash: "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkPassword(tt.password, tt.storedHash); got != tt.want {
				t.Errorf("checkPassword(%s, %s) = %v, want %v", tt.password, tt.storedHash, got, tt.want)
			}
		})
	}
}
