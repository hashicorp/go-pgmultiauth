package pgmultiauth

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2/google"
)

func Test_Config_validate(t *testing.T) {
	// Create a logger for tests
	logger := hclog.NewNullLogger()

	tests := []struct {
		name        string
		config      Config
		expectedErr bool
		errContains string
	}{
		{
			name: "Valid config with no auth",
			config: Config{
				DatabaseURL: "postgres://user@host:5432/db",
				Logger:      logger,
				AuthMethod:  StandardAuth,
			},
			expectedErr: false,
		},
		{
			name: "Valid config with AWS auth",
			config: Config{
				DatabaseURL: "postgres://user@host:5432/db",
				Logger:      logger,
				AuthMethod:  AWSAuth,
				AWSConfig: &aws.Config{
					Region:      "us-west-2",
					Credentials: aws.AnonymousCredentials{},
				},
			},
			expectedErr: false,
		},
		{
			name: "Valid config with GCP auth",
			config: Config{
				DatabaseURL: "postgres://user@host:5432/db",
				Logger:      logger,
				AuthMethod:  GCPAuth,
				GoogleCreds: &google.Credentials{},
			},
			expectedErr: false,
		},
		{
			name: "Valid config with Azure auth",
			config: Config{
				DatabaseURL: "postgres://user@host:5432/db",
				Logger:      logger,
				AuthMethod:  AzureAuth,
				AzureCreds:  &MockTokenCredential{},
			},
			expectedErr: false,
		},
		{
			name: "Empty DatabaseURL",
			config: Config{
				DatabaseURL: "",
				Logger:      logger,
				AuthMethod:  StandardAuth,
			},
			expectedErr: true,
			errContains: "databaseURL cannot be empty",
		},
		{
			name: "Nil Logger",
			config: Config{
				DatabaseURL: "postgres://user@host:5432/db",
				Logger:      nil,
				AuthMethod:  StandardAuth,
			},
			expectedErr: true,
			errContains: "logger cannot be nil",
		},
		{
			name: "AWS auth without aws config",
			config: Config{
				DatabaseURL: "postgres://user@host:5432/db",
				Logger:      logger,
				AuthMethod:  AWSAuth,
			},
			expectedErr: true,
			errContains: "AWSConfig is required when AuthMethod is AWSAuth",
		},
		{
			name: "AWS auth without region in aws config",
			config: Config{
				DatabaseURL: "postgres://user@host:5432/db",
				Logger:      logger,
				AuthMethod:  AWSAuth,
				AWSConfig: &aws.Config{
					Credentials: aws.AnonymousCredentials{},
				},
			},
			expectedErr: true,
			errContains: "region is required in AWSConfig when AuthMethod is AWSAuth",
		},
		{
			name: "AWS auth without credentials in aws config",
			config: Config{
				DatabaseURL: "postgres://user@host:5432/db",
				Logger:      logger,
				AuthMethod:  AWSAuth,
				AWSConfig: &aws.Config{
					Region: "us-west-2",
				},
			},
			expectedErr: true,
			errContains: "credentials are required in AWSConfig when AuthMethod is AWSAuth",
		},
		{
			name: "Azure auth without AzureCreds",
			config: Config{
				DatabaseURL: "postgres://user@host:5432/db",
				Logger:      logger,
				AuthMethod:  AzureAuth,
			},
			expectedErr: true,
			errContains: "AzureCreds is required when AuthMethod is AzureAuth",
		},
		{
			name: "Unsupported auth method",
			config: Config{
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

func Test_Config_authConfigured(t *testing.T) {
	logger := hclog.NewNullLogger()

	tests := []struct {
		name     string
		config   Config
		expected bool
	}{
		{
			name: "No authentication configured",
			config: Config{
				DatabaseURL: "postgres://user@host:5432/db",
				Logger:      logger,
				AuthMethod:  StandardAuth,
			},
			expected: false,
		},
		{
			name: "AWS authentication configured",
			config: Config{
				DatabaseURL: "postgres://user@host:5432/db",
				Logger:      logger,
				AuthMethod:  AWSAuth,
				AWSConfig:   &aws.Config{},
			},
			expected: true,
		},
		{
			name: "GCP authentication configured",
			config: Config{
				DatabaseURL: "postgres://user@host:5432/db",
				Logger:      logger,
				AuthMethod:  GCPAuth,
			},
			expected: true,
		},
		{
			name: "Azure authentication configured",
			config: Config{
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
		name         string
		useAWSAuth   bool
		useGCPAuth   bool
		useAzureAuth bool
		want         AuthMethod
	}{
		{
			name:         "No auth method specified",
			useAWSAuth:   false,
			useGCPAuth:   false,
			useAzureAuth: false,
			want:         StandardAuth,
		},
		{
			name:         "AWS auth only",
			useAWSAuth:   true,
			useGCPAuth:   false,
			useAzureAuth: false,
			want:         AWSAuth,
		},
		{
			name:         "GCP auth only",
			useAWSAuth:   false,
			useGCPAuth:   true,
			useAzureAuth: false,
			want:         GCPAuth,
		},
		{
			name:         "Azure auth only",
			useAWSAuth:   false,
			useGCPAuth:   false,
			useAzureAuth: true,
			want:         AzureAuth,
		},
		{
			name:         "AWS prioritized over GCP",
			useAWSAuth:   true,
			useGCPAuth:   true,
			useAzureAuth: false,
			want:         AWSAuth,
		},
		{
			name:         "AWS prioritized over Azure",
			useAWSAuth:   true,
			useGCPAuth:   false,
			useAzureAuth: true,
			want:         AWSAuth,
		},
		{
			name:         "GCP prioritized over Azure",
			useAWSAuth:   false,
			useGCPAuth:   true,
			useAzureAuth: true,
			want:         GCPAuth,
		},
		{
			name:         "AWS prioritized over all others",
			useAWSAuth:   true,
			useGCPAuth:   true,
			useAzureAuth: true,
			want:         AWSAuth,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetAuthMode(tt.useAWSAuth, tt.useGCPAuth, tt.useAzureAuth)
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
