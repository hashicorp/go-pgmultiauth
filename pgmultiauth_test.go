// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pgmultiauth

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
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
				connString: "postgres://user@host:5432/db",
				logger:     logger,
				authMethod: StandardAuth,
			},
			expectedErr: false,
		},
		{
			name: "Valid config with AWS auth",
			config: Config{
				connString: "postgres://user@host:5432/db",
				logger:     logger,
				authMethod: AWSAuth,
				awsConfig: &aws.Config{
					Region:      "us-west-2",
					Credentials: aws.AnonymousCredentials{},
				},
			},
			expectedErr: false,
		},
		{
			name: "Valid config with GCP auth",
			config: Config{
				connString: "postgres://user@host:5432/db",
				logger:     logger,
				authMethod: GCPAuth,
				googleCreds: &google.Credentials{
					TokenSource: oauth2.StaticTokenSource(&oauth2.Token{}),
				},
			},
			expectedErr: false,
		},
		{
			name: "Valid config with Azure auth",
			config: Config{
				connString: "postgres://user@host:5432/db",
				logger:     logger,
				authMethod: AzureAuth,
				azureCreds: &MockTokenCredential{},
			},
			expectedErr: false,
		},
		{
			name: "Empty Database Connection String",
			config: Config{
				connString: "",
				logger:     logger,
				authMethod: StandardAuth,
			},
			expectedErr: true,
			errContains: "connString cannot be empty",
		},
		{
			name: "Nil logger",
			config: Config{
				connString: "postgres://user@host:5432/db",
				logger:     nil,
				authMethod: StandardAuth,
			},
			expectedErr: true,
			errContains: "logger cannot be nil",
		},
		{
			name: "AWS auth without aws config",
			config: Config{
				connString: "postgres://user@host:5432/db",
				logger:     logger,
				authMethod: AWSAuth,
			},
			expectedErr: true,
			errContains: "invalid AWS config: aws config is required for AWS authentication",
		},
		{
			name: "AWS auth without region in aws config",
			config: Config{
				connString: "postgres://user@host:5432/db",
				logger:     logger,
				authMethod: AWSAuth,
				awsConfig: &aws.Config{
					Credentials: aws.AnonymousCredentials{},
				},
			},
			expectedErr: true,
			errContains: "invalid AWS config: aws region is required for AWS authentication",
		},
		{
			name: "AWS auth without credentials in aws config",
			config: Config{
				connString: "postgres://user@host:5432/db",
				logger:     logger,
				authMethod: AWSAuth,
				awsConfig: &aws.Config{
					Region: "us-west-2",
				},
			},
			expectedErr: true,
			errContains: "invalid AWS config: aws credentials are required for AWS authentication",
		},
		{
			name: "Azure auth without AzureCreds",
			config: Config{
				connString: "postgres://user@host:5432/db",
				logger:     logger,
				authMethod: AzureAuth,
			},
			expectedErr: true,
			errContains: "invalid Azure config: azure credentials are required for Azure authentication",
		},
		{
			name: "GCP auth without Credentials",
			config: Config{
				connString: "postgres://user@host:5432/db",
				logger:     logger,
				authMethod: GCPAuth,
			},
			expectedErr: true,
			errContains: "invalid GCP config: gcp credentials are required for GCP authentication",
		},
		{
			name: "Unsupported auth method",
			config: Config{
				connString: "postgres://user@host:5432/db",
				logger:     logger,
				authMethod: AuthMethod(99), // Invalid value
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
				connString: "postgres://user@host:5432/db",
				logger:     logger,
				authMethod: StandardAuth,
			},
			expected: false,
		},
		{
			name: "AWS authentication configured",
			config: Config{
				connString: "postgres://user@host:5432/db",
				logger:     logger,
				authMethod: AWSAuth,
				awsConfig:  &aws.Config{},
			},
			expected: true,
		},
		{
			name: "GCP authentication configured",
			config: Config{
				connString: "postgres://user@host:5432/db",
				logger:     logger,
				authMethod: GCPAuth,
			},
			expected: true,
		},
		{
			name: "Azure authentication configured",
			config: Config{
				connString: "postgres://user@host:5432/db",
				logger:     logger,
				authMethod: AzureAuth,
				azureCreds: &MockTokenCredential{},
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

func Test_replaceDBPassword(t *testing.T) {
	tests := []struct {
		name               string
		inputconnString    string
		newPassword        string
		expectedconnString string
		expectError        bool
	}{
		{
			name:               "Basic URL with password",
			inputconnString:    "postgres://user:oldpass@localhost:5432/mydb",
			newPassword:        "newpass",
			expectedconnString: "postgres://user:newpass@localhost:5432/mydb",
			expectError:        false,
		},
		{
			name:               "Basic postgresql URL with password",
			inputconnString:    "postgresql://user:oldpass@localhost:5432/mydb",
			newPassword:        "newpass",
			expectedconnString: "postgresql://user:newpass@localhost:5432/mydb",
			expectError:        false,
		},
		{
			name:               "URL without password",
			inputconnString:    "postgres://user@localhost:5432/mydb",
			newPassword:        "newpass",
			expectedconnString: "postgres://user:newpass@localhost:5432/mydb",
			expectError:        false,
		},
		{
			name:               "URL without password with :",
			inputconnString:    "postgres://user:@localhost:5432/mydb",
			newPassword:        "newpass",
			expectedconnString: "postgres://user:newpass@localhost:5432/mydb",
			expectError:        false,
		},
		{
			name:               "URL with search_path",
			inputconnString:    "postgres://user:oldpass@localhost:5432/mydb?options=-c%20search_path=rails",
			newPassword:        "newpass",
			expectedconnString: "postgres://user:newpass@localhost:5432/mydb?options=-c%20search_path=rails",
			expectError:        false,
		},
		{
			name:               "URL with multiple query parameters",
			inputconnString:    "postgres://user:oldpass@localhost:5432/mydb?options=-c%20search_path%3Drails&sslmode=disable",
			newPassword:        "newpass",
			expectedconnString: "postgres://user:newpass@localhost:5432/mydb?options=-c%20search_path%3Drails&sslmode=disable",
			expectError:        false,
		},
		{
			name:               "URL with special characters in password",
			inputconnString:    "postgres://user:old%40pass@localhost:5432/mydb",
			newPassword:        "new@pass&special!",
			expectedconnString: "postgres://user:new%40pass%26special%21@localhost:5432/mydb",
			expectError:        false,
		},
		{
			name:               "URL with options parameter",
			inputconnString:    "postgres://user:oldpass@localhost:5432/mydb?options=-c%20statement_timeout%3D5000",
			newPassword:        "newpass",
			expectedconnString: "postgres://user:newpass@localhost:5432/mydb?options=-c%20statement_timeout%3D5000",
			expectError:        false,
		},
		{
			name:               "Invalid URL",
			inputconnString:    "postgres://user:oldp/mydb",
			newPassword:        "newpass",
			expectedconnString: "",
			expectError:        true,
		},
		{
			name:               "DSN string with no password",
			inputconnString:    "user=foo dbname=bar host=localhost port=5432 sslmode=disable",
			newPassword:        "newpass",
			expectedconnString: "user=foo dbname=bar host=localhost port=5432 sslmode=disable password='newpass'",
			expectError:        false,
		},
		{
			name:               "DSN string with password",
			inputconnString:    "user=foo password=existingPass dbname=bar host=localhost port=5432 sslmode=disable",
			newPassword:        "newpass",
			expectedconnString: "user=foo password='newpass' dbname=bar host=localhost port=5432 sslmode=disable",
			expectError:        false,
		},
		{
			name:               "DSN string with special characters in password",
			inputconnString:    "user=foo dbname=bar host=localhost port=5432 sslmode=disable",
			newPassword:        "new@pass&special!",
			expectedconnString: "user=foo dbname=bar host=localhost port=5432 sslmode=disable password='new@pass&special!'",
			expectError:        false,
		},
		{
			name:               "DSN string with `'` in new password",
			inputconnString:    "user=foo dbname=bar host=localhost port=5432 sslmode=disable",
			newPassword:        "new'pass",
			expectedconnString: "user=foo dbname=bar host=localhost port=5432 sslmode=disable password='new''pass'",
			expectError:        false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := replaceDBPassword(tc.inputconnString, tc.newPassword)

			if tc.expectError && err == nil {
				t.Errorf("Expected error but got none")
				return
			}

			if !tc.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
				return
			}

			if !tc.expectError {
				if result != tc.expectedconnString {
					t.Errorf("Expected URL: %s, but got: %s", tc.expectedconnString, result)
				}
			}
		})
	}
}
