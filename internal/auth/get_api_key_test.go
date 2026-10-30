package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		auth       string
		wantKey    string
		wantErr    bool
		wantNoAuth bool
	}{
		{
			name:    "valid API key",
			auth:    "ApiKey test-key-123",
			wantKey: "test-key-123",
		},
		{
			name:       "missing authorization header",
			wantErr:    true,
			wantNoAuth: true,
		},
		{
			name:    "wrong authentication scheme",
			auth:    "Bearer test-key-123",
			wantErr: true,
		},
		{
			name:    "missing API key",
			auth:    "ApiKey",
			wantErr: true,
		},
		{
			name:    "incorrect scheme capitalization",
			auth:    "apikey test-key-123",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := make(http.Header)
			if tt.auth != "" {
				headers.Set("Authorization", tt.auth)
			}

			gotKey, err := GetAPIKey(headers)

			if (err != nil) != tt.wantErr {
				t.Fatalf(
					"GetAPIKey() error = %v, wantErr = %v",
					err,
					tt.wantErr,
				)
			}

			if tt.wantNoAuth && !errors.Is(err, ErrNoAuthHeaderIncluded) {
				t.Errorf(
					"GetAPIKey() error = %v, want %v",
					err,
					ErrNoAuthHeaderIncluded,
				)
			}

			if gotKey != tt.wantKey {
				t.Errorf(
					"GetAPIKey() key = %q, want %q",
					gotKey,
					tt.wantKey,
				)
			}
		})
	}
}
