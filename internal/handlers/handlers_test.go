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
