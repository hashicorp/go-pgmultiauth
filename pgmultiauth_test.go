// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package pgmultiauth

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"

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

func Test_resolveIRSAConfig(t *testing.T) {
	tests := []struct {
		name          string
		roleARN       string
		tokenFile     string
		envRoleARN    string
		envTokenFile  string
		expectedRole  string
		expectedToken string
	}{
		{
			name:          "Explicit values take precedence over env vars",
			roleARN:       "arn:aws:iam::123456789012:role/explicit-role",
			tokenFile:     "/var/run/secrets/explicit-token",
			envRoleARN:    "arn:aws:iam::999999999999:role/env-role",
			envTokenFile:  "/var/run/secrets/env-token",
			expectedRole:  "arn:aws:iam::123456789012:role/explicit-role",
			expectedToken: "/var/run/secrets/explicit-token",
		},
		{
			name:          "Falls back to env vars when options are empty",
			roleARN:       "",
			tokenFile:     "",
			envRoleARN:    "arn:aws:iam::123456789012:role/env-role",
			envTokenFile:  "/var/run/secrets/eks/serviceaccount/token",
			expectedRole:  "arn:aws:iam::123456789012:role/env-role",
			expectedToken: "/var/run/secrets/eks/serviceaccount/token",
		},
		{
			name:          "No IRSA configured",
			roleARN:       "",
			tokenFile:     "",
			envRoleARN:    "",
			envTokenFile:  "",
			expectedRole:  "",
			expectedToken: "",
		},
		{
			name:          "Explicit role ARN with env token file",
			roleARN:       "arn:aws:iam::123456789012:role/explicit-role",
			tokenFile:     "",
			envRoleARN:    "",
			envTokenFile:  "/var/run/secrets/env-token",
			expectedRole:  "arn:aws:iam::123456789012:role/explicit-role",
			expectedToken: "/var/run/secrets/env-token",
		},
		{
			name:          "Env role ARN with explicit token file",
			roleARN:       "",
			tokenFile:     "/var/run/secrets/explicit-token",
			envRoleARN:    "arn:aws:iam::123456789012:role/env-role",
			envTokenFile:  "",
			expectedRole:  "arn:aws:iam::123456789012:role/env-role",
			expectedToken: "/var/run/secrets/explicit-token",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AWS_ROLE_ARN", tc.envRoleARN)
			t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", tc.envTokenFile)

			role, token := resolveIRSAConfig(tc.roleARN, tc.tokenFile)

			require.Equal(t, tc.expectedRole, role)
			require.Equal(t, tc.expectedToken, token)
		})
	}
}

func Test_configureIRSACredentials(t *testing.T) {
	tests := []struct {
		name               string
		roleARN            string
		tokenFile          string
		expectCredsSwapped bool
	}{
		{
			name:               "Both role ARN and token file set",
			roleARN:            "arn:aws:iam::123456789012:role/test-role",
			tokenFile:          "/var/run/secrets/eks/serviceaccount/token",
			expectCredsSwapped: true,
		},
		{
			name:               "Only role ARN set",
			roleARN:            "arn:aws:iam::123456789012:role/test-role",
			tokenFile:          "",
			expectCredsSwapped: false,
		},
		{
			name:               "Only token file set",
			roleARN:            "",
			tokenFile:          "/var/run/secrets/eks/serviceaccount/token",
			expectCredsSwapped: false,
		},
		{
			name:               "Neither set",
			roleARN:            "",
			tokenFile:          "",
			expectCredsSwapped: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			originalCreds := aws.AnonymousCredentials{}
			cfg := aws.Config{
				Region:      "us-west-2",
				Credentials: originalCreds,
			}

			configureIRSACredentials(&cfg, tc.roleARN, tc.tokenFile)

			if tc.expectCredsSwapped {
				// When IRSA is configured, credentials should be replaced
				// with a CredentialsCache wrapping the web identity provider
				_, isAnonymous := cfg.Credentials.(aws.AnonymousCredentials)
				require.False(t, isAnonymous, "Expected credentials to be replaced with IRSA provider")
			} else {
				// Credentials should remain unchanged
				_, isAnonymous := cfg.Credentials.(aws.AnonymousCredentials)
				require.True(t, isAnonymous, "Expected credentials to remain unchanged")
			}
		})
	}
}

func Test_Config_validate_IRSA(t *testing.T) {
	logger := hclog.NewNullLogger()

	// Simulate IRSA-resolved credentials by using a mock credentials provider.
	// On EKS with IRSA, the AWS SDK resolves credentials via the web identity
	// token, resulting in a non-nil CredentialsProvider on the aws.Config.
	irsaCreds := aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
		return aws.Credentials{
			AccessKeyID:     "ASIAMOCKKEY",
			SecretAccessKey: "mockSecret",
			SessionToken:    "mockSessionToken",
			Source:          "WebIdentityToken",
		}, nil
	})

	tests := []struct {
		name        string
		config      Config
		expectedErr bool
		errContains string
	}{
		{
			name: "Valid config with IRSA credentials",
			config: Config{
				connString: "postgres://user@host:5432/db",
				logger:     logger,
				authMethod: AWSAuth,
				awsConfig: &aws.Config{
					Region:      "us-west-2",
					Credentials: irsaCreds,
				},
			},
			expectedErr: false,
		},
		{
			name: "IRSA credentials with missing region",
			config: Config{
				connString: "postgres://user@host:5432/db",
				logger:     logger,
				authMethod: AWSAuth,
				awsConfig: &aws.Config{
					Credentials: irsaCreds,
				},
			},
			expectedErr: true,
			errContains: "invalid AWS config: aws region is required for AWS authentication",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.validate()
			if tt.expectedErr {
				require.Error(t, err)
				require.EqualError(t, err, tt.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// mockSTSClient implements stsCallerIdentityAPI for testing.
type mockSTSClient struct {
	output *sts.GetCallerIdentityOutput
	err    error
}

func (m *mockSTSClient) GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return m.output, m.err
}

func Test_validateAWSIdentityWithClient(t *testing.T) {
	tests := []struct {
		name        string
		client      stsCallerIdentityAPI
		expected    *AWSCallerIdentity
		expectedErr bool
		errContains string
	}{
		{
			name: "Successful identity validation",
			client: &mockSTSClient{
				output: &sts.GetCallerIdentityOutput{
					Account: aws.String("123456789012"),
					Arn:     aws.String("arn:aws:sts::123456789012:assumed-role/my-irsa-role/session"),
					UserId:  aws.String("AROA3XFRBF23:session"),
				},
			},
			expected: &AWSCallerIdentity{
				Account: "123456789012",
				ARN:     "arn:aws:sts::123456789012:assumed-role/my-irsa-role/session",
				UserID:  "AROA3XFRBF23:session",
			},
		},
		{
			name: "IRSA assumed-role identity",
			client: &mockSTSClient{
				output: &sts.GetCallerIdentityOutput{
					Account: aws.String("111122223333"),
					Arn:     aws.String("arn:aws:sts::111122223333:assumed-role/eks-irsa-tfe-postgres/aws-sdk-go-v2-1234567890"),
					UserId:  aws.String("AROAEXAMPLE:aws-sdk-go-v2-1234567890"),
				},
			},
			expected: &AWSCallerIdentity{
				Account: "111122223333",
				ARN:     "arn:aws:sts::111122223333:assumed-role/eks-irsa-tfe-postgres/aws-sdk-go-v2-1234567890",
				UserID:  "AROAEXAMPLE:aws-sdk-go-v2-1234567890",
			},
		},
		{
			name: "STS call fails",
			client: &mockSTSClient{
				err: fmt.Errorf("ExpiredTokenException: token has expired"),
			},
			expectedErr: true,
			errContains: "sts GetCallerIdentity",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			identity, err := validateAWSIdentityWithClient(context.Background(), tc.client)

			if tc.expectedErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errContains)
				require.Nil(t, identity)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expected, identity)
			}
		})
	}
}
