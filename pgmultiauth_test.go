package pgmultiauth

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2/google"
)

func Test_AuthConfig_validate(t *testing.T) {
	// Create a logger for tests
	logger := hclog.NewNullLogger()

	tests := []struct {
		name        string
		config      AuthConfig
		expectedErr bool
		errContains string
	}{
		{
			name: "Valid config with no auth",
			config: AuthConfig{
				DatabaseURL: "postgres://user@host:5432/db",
				Logger:      logger,
				AuthMethod:  NoAuth,
			},
			expectedErr: false,
		},
		{
			name: "Valid config with AWS IAM auth",
			config: AuthConfig{
				DatabaseURL: "postgres://user@host:5432/db",
				Logger:      logger,
				AuthMethod:  AWSIAMAuth,
				AWSConfig:   &aws.Config{},
			},
			expectedErr: false,
		},
		{
			name: "Valid config with GCP auth",
			config: AuthConfig{
				DatabaseURL: "postgres://user@host:5432/db",
				Logger:      logger,
				AuthMethod:  GCPAuth,
				GoogleCreds: &google.Credentials{},
			},
			expectedErr: false,
		},
		{
			name: "Valid config with Azure auth",
			config: AuthConfig{
				DatabaseURL: "postgres://user@host:5432/db",
				Logger:      logger,
				AuthMethod:  AzureAuth,
				AzureCreds:  &MockTokenCredential{},
			},
			expectedErr: false,
		},
		{
			name: "Azure auth without client ID",
			config: AuthConfig{
				DatabaseURL: "postgres://user@host:5432/db",
				Logger:      logger,
				AuthMethod:  AzureAuth,
				AzureCreds:  &MockTokenCredential{},
			},
			expectedErr: false,
		},
		{
			name: "Empty DatabaseURL",
			config: AuthConfig{
				DatabaseURL: "",
				Logger:      logger,
				AuthMethod:  NoAuth,
			},
			expectedErr: true,
			errContains: "databaseURL cannot be empty",
		},
		{
			name: "Nil Logger",
			config: AuthConfig{
				DatabaseURL: "postgres://user@host:5432/db",
				Logger:      nil,
				AuthMethod:  NoAuth,
			},
			expectedErr: true,
			errContains: "logger cannot be nil",
		},
		{
			name: "AWS auth without aws config",
			config: AuthConfig{
				DatabaseURL: "postgres://user@host:5432/db",
				Logger:      logger,
				AuthMethod:  AWSIAMAuth,
			},
			expectedErr: true,
			errContains: "AWSConfig is required when AuthMethod is AWSIAMAuth",
		},
		{
			name: "Azure auth without Azure Cr",
			config: AuthConfig{
				DatabaseURL: "postgres://user@host:5432/db",
				Logger:      logger,
				AuthMethod:  AzureAuth,
			},
			expectedErr: true,
			errContains: "AzureCreds is required when AuthMethod is AzureAuth",
		},
		{
			name: "Unsupported auth method",
			config: AuthConfig{
				DatabaseURL: "postgres://user@host:5432/db",
				Logger:      logger,
				AuthMethod:  AuthMethod(99), // Invalid value
			},
			expectedErr: true,
			errContains: "unsupported authentication method: 99",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.validate()

			// Check if we expected an error
			if tt.expectedErr {
				require.Error(t, err, "Expected an error but got nil")
				require.EqualError(t, err, tt.errContains, "Error message does not match")
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}

func Test_AuthConfig_authConfigured(t *testing.T) {
	logger := hclog.NewNullLogger()

	tests := []struct {
		name     string
		config   AuthConfig
		expected bool
	}{
		{
			name: "No authentication configured",
			config: AuthConfig{
				DatabaseURL: "postgres://user@host:5432/db",
				Logger:      logger,
				AuthMethod:  NoAuth,
			},
			expected: false,
		},
		{
			name: "AWS IAM authentication configured",
			config: AuthConfig{
				DatabaseURL: "postgres://user@host:5432/db",
				Logger:      logger,
				AuthMethod:  AWSIAMAuth,
				AWSConfig:   &aws.Config{},
			},
			expected: true,
		},
		{
			name: "GCP authentication configured",
			config: AuthConfig{
				DatabaseURL: "postgres://user@host:5432/db",
				Logger:      logger,
				AuthMethod:  GCPAuth,
			},
			expected: true,
		},
		{
			name: "Azure authentication configured",
			config: AuthConfig{
				DatabaseURL: "postgres://user@host:5432/db",
				Logger:      logger,
				AuthMethod:  AzureAuth,
				AzureCreds:  &MockTokenCredential{},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.authConfigured()
			if result != tt.expected {
				t.Errorf("authConfigured() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func Test_GetAuthMode(t *testing.T) {
	tests := []struct {
		name          string
		useAWSIAMAuth bool
		useGCPAuth    bool
		useAzureAuth  bool
		want          AuthMethod
	}{
		{
			name:          "No auth method specified",
			useAWSIAMAuth: false,
			useGCPAuth:    false,
			useAzureAuth:  false,
			want:          NoAuth,
		},
		{
			name:          "AWS IAM auth only",
			useAWSIAMAuth: true,
			useGCPAuth:    false,
			useAzureAuth:  false,
			want:          AWSIAMAuth,
		},
		{
			name:          "GCP auth only",
			useAWSIAMAuth: false,
			useGCPAuth:    true,
			useAzureAuth:  false,
			want:          GCPAuth,
		},
		{
			name:          "Azure auth only",
			useAWSIAMAuth: false,
			useGCPAuth:    false,
			useAzureAuth:  true,
			want:          AzureAuth,
		},
		{
			name:          "AWS prioritized over GCP",
			useAWSIAMAuth: true,
			useGCPAuth:    true,
			useAzureAuth:  false,
			want:          AWSIAMAuth,
		},
		{
			name:          "AWS prioritized over Azure",
			useAWSIAMAuth: true,
			useGCPAuth:    false,
			useAzureAuth:  true,
			want:          AWSIAMAuth,
		},
		{
			name:          "GCP prioritized over Azure",
			useAWSIAMAuth: false,
			useGCPAuth:    true,
			useAzureAuth:  true,
			want:          GCPAuth,
		},
		{
			name:          "AWS prioritized over all others",
			useAWSIAMAuth: true,
			useGCPAuth:    true,
			useAzureAuth:  true,
			want:          AWSIAMAuth,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetAuthMode(tt.useAWSIAMAuth, tt.useGCPAuth, tt.useAzureAuth)
			if got != tt.want {
				t.Errorf("GetAuthMode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_replaceDBPassword(t *testing.T) {
	tests := []struct {
		name        string
		inputURL    string
		newPassword string
		expectedURL string
		expectError bool
	}{
		{
			name:        "Basic URL with password",
			inputURL:    "postgres://user:oldpass@localhost:5432/mydb",
			newPassword: "newpass",
			expectedURL: "postgres://user:newpass@localhost:5432/mydb",
			expectError: false,
		},
		{
			name:        "Basic postgresql URL with password",
			inputURL:    "postgresql://user:oldpass@localhost:5432/mydb",
			newPassword: "newpass",
			expectedURL: "postgresql://user:newpass@localhost:5432/mydb",
			expectError: false,
		},
		{
			name:        "URL without password",
			inputURL:    "postgres://user@localhost:5432/mydb",
			newPassword: "newpass",
			expectedURL: "postgres://user:newpass@localhost:5432/mydb",
			expectError: false,
		},
		{
			name:        "URL without password with :",
			inputURL:    "postgres://user:@localhost:5432/mydb",
			newPassword: "newpass",
			expectedURL: "postgres://user:newpass@localhost:5432/mydb",
			expectError: false,
		},
		{
			name:        "URL with search_path",
			inputURL:    "postgres://user:oldpass@localhost:5432/mydb?options=-c%20search_path=rails",
			newPassword: "newpass",
			expectedURL: "postgres://user:newpass@localhost:5432/mydb?options=-c%20search_path=rails",
			expectError: false,
		},
		{
			name:        "URL with multiple query parameters",
			inputURL:    "postgres://user:oldpass@localhost:5432/mydb?options=-c%20search_path%3Drails&sslmode=disable",
			newPassword: "newpass",
			expectedURL: "postgres://user:newpass@localhost:5432/mydb?options=-c%20search_path%3Drails&sslmode=disable",
			expectError: false,
		},
		{
			name:        "URL with special characters in password",
			inputURL:    "postgres://user:old%40pass@localhost:5432/mydb",
			newPassword: "new@pass&special!",
			expectedURL: "postgres://user:new%40pass%26special%21@localhost:5432/mydb",
			expectError: false,
		},
		{
			name:        "URL with options parameter",
			inputURL:    "postgres://user:oldpass@localhost:5432/mydb?options=-c%20statement_timeout%3D5000",
			newPassword: "newpass",
			expectedURL: "postgres://user:newpass@localhost:5432/mydb?options=-c%20statement_timeout%3D5000",
			expectError: false,
		},
		{
			name:        "Invalid URL",
			inputURL:    "postgres://user:oldp/mydb",
			newPassword: "newpass",
			expectedURL: "",
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := replaceDBPassword(tc.inputURL, tc.newPassword)

			if tc.expectError && err == nil {
				t.Errorf("Expected error but got none")
				return
			}

			if !tc.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
				return
			}

			if !tc.expectError {
				if result != tc.expectedURL {
					t.Errorf("Expected URL: %s, but got: %s", tc.expectedURL, result)
				}
			}
		})
	}
}
