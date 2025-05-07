package pgmultiauth

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
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
				ConnString: "postgres://user@host:5432/db",
				Logger:     logger,
				AuthMethod: StandardAuth,
			},
			expectedErr: false,
		},
		{
			name: "Valid config with AWS auth",
			config: Config{
				ConnString: "postgres://user@host:5432/db",
				Logger:     logger,
				AuthMethod: AWSAuth,
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
				ConnString: "postgres://user@host:5432/db",
				Logger:     logger,
				AuthMethod: GCPAuth,
				GoogleCreds: &google.Credentials{
					TokenSource: oauth2.StaticTokenSource(&oauth2.Token{}),
				},
			},
			expectedErr: false,
		},
		{
			name: "Valid config with Azure auth",
			config: Config{
				ConnString: "postgres://user@host:5432/db",
				Logger:     logger,
				AuthMethod: AzureAuth,
				AzureCreds: &MockTokenCredential{},
			},
			expectedErr: false,
		},
		{
			name: "Empty Database Connection String",
			config: Config{
				ConnString: "",
				Logger:     logger,
				AuthMethod: StandardAuth,
			},
			expectedErr: true,
			errContains: "ConnString cannot be empty",
		},
		{
			name: "Nil Logger",
			config: Config{
				ConnString: "postgres://user@host:5432/db",
				Logger:     nil,
				AuthMethod: StandardAuth,
			},
			expectedErr: true,
			errContains: "logger cannot be nil",
		},
		{
			name: "AWS auth without aws config",
			config: Config{
				ConnString: "postgres://user@host:5432/db",
				Logger:     logger,
				AuthMethod: AWSAuth,
			},
			expectedErr: true,
			errContains: "invalid AWS config: aws config is required for AWS authentication",
		},
		{
			name: "AWS auth without region in aws config",
			config: Config{
				ConnString: "postgres://user@host:5432/db",
				Logger:     logger,
				AuthMethod: AWSAuth,
				AWSConfig: &aws.Config{
					Credentials: aws.AnonymousCredentials{},
				},
			},
			expectedErr: true,
			errContains: "invalid AWS config: aws region is required for AWS authentication",
		},
		{
			name: "AWS auth without credentials in aws config",
			config: Config{
				ConnString: "postgres://user@host:5432/db",
				Logger:     logger,
				AuthMethod: AWSAuth,
				AWSConfig: &aws.Config{
					Region: "us-west-2",
				},
			},
			expectedErr: true,
			errContains: "invalid AWS config: aws credentials are required for AWS authentication",
		},
		{
			name: "Azure auth without AzureCreds",
			config: Config{
				ConnString: "postgres://user@host:5432/db",
				Logger:     logger,
				AuthMethod: AzureAuth,
			},
			expectedErr: true,
			errContains: "invalid Azure config: azure credentials are required for Azure authentication",
		},
		{
			name: "GCP auth without Credentials",
			config: Config{
				ConnString: "postgres://user@host:5432/db",
				Logger:     logger,
				AuthMethod: GCPAuth,
			},
			expectedErr: true,
			errContains: "invalid GCP config: gcp credentials are required for GCP authentication",
		},
		{
			name: "Unsupported auth method",
			config: Config{
				ConnString: "postgres://user@host:5432/db",
				Logger:     logger,
				AuthMethod: AuthMethod(99), // Invalid value
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
				ConnString: "postgres://user@host:5432/db",
				Logger:     logger,
				AuthMethod: StandardAuth,
			},
			expected: false,
		},
		{
			name: "AWS authentication configured",
			config: Config{
				ConnString: "postgres://user@host:5432/db",
				Logger:     logger,
				AuthMethod: AWSAuth,
				AWSConfig:  &aws.Config{},
			},
			expected: true,
		},
		{
			name: "GCP authentication configured",
			config: Config{
				ConnString: "postgres://user@host:5432/db",
				Logger:     logger,
				AuthMethod: GCPAuth,
			},
			expected: true,
		},
		{
			name: "Azure authentication configured",
			config: Config{
				ConnString: "postgres://user@host:5432/db",
				Logger:     logger,
				AuthMethod: AzureAuth,
				AzureCreds: &MockTokenCredential{},
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
		name               string
		inputConnString    string
		newPassword        string
		expectedConnString string
		expectError        bool
	}{
		{
			name:               "Basic URL with password",
			inputConnString:    "postgres://user:oldpass@localhost:5432/mydb",
			newPassword:        "newpass",
			expectedConnString: "postgres://user:newpass@localhost:5432/mydb",
			expectError:        false,
		},
		{
			name:               "Basic postgresql URL with password",
			inputConnString:    "postgresql://user:oldpass@localhost:5432/mydb",
			newPassword:        "newpass",
			expectedConnString: "postgresql://user:newpass@localhost:5432/mydb",
			expectError:        false,
		},
		{
			name:               "URL without password",
			inputConnString:    "postgres://user@localhost:5432/mydb",
			newPassword:        "newpass",
			expectedConnString: "postgres://user:newpass@localhost:5432/mydb",
			expectError:        false,
		},
		{
			name:               "URL without password with :",
			inputConnString:    "postgres://user:@localhost:5432/mydb",
			newPassword:        "newpass",
			expectedConnString: "postgres://user:newpass@localhost:5432/mydb",
			expectError:        false,
		},
		{
			name:               "URL with search_path",
			inputConnString:    "postgres://user:oldpass@localhost:5432/mydb?options=-c%20search_path=rails",
			newPassword:        "newpass",
			expectedConnString: "postgres://user:newpass@localhost:5432/mydb?options=-c%20search_path=rails",
			expectError:        false,
		},
		{
			name:               "URL with multiple query parameters",
			inputConnString:    "postgres://user:oldpass@localhost:5432/mydb?options=-c%20search_path%3Drails&sslmode=disable",
			newPassword:        "newpass",
			expectedConnString: "postgres://user:newpass@localhost:5432/mydb?options=-c%20search_path%3Drails&sslmode=disable",
			expectError:        false,
		},
		{
			name:               "URL with special characters in password",
			inputConnString:    "postgres://user:old%40pass@localhost:5432/mydb",
			newPassword:        "new@pass&special!",
			expectedConnString: "postgres://user:new%40pass%26special%21@localhost:5432/mydb",
			expectError:        false,
		},
		{
			name:               "URL with options parameter",
			inputConnString:    "postgres://user:oldpass@localhost:5432/mydb?options=-c%20statement_timeout%3D5000",
			newPassword:        "newpass",
			expectedConnString: "postgres://user:newpass@localhost:5432/mydb?options=-c%20statement_timeout%3D5000",
			expectError:        false,
		},
		{
			name:               "Invalid URL",
			inputConnString:    "postgres://user:oldp/mydb",
			newPassword:        "newpass",
			expectedConnString: "",
			expectError:        true,
		},
		{
			name:               "DSN string with no password",
			inputConnString:    "user=foo dbname=bar host=localhost port=5432 sslmode=disable",
			newPassword:        "newpass",
			expectedConnString: "user=foo dbname=bar host=localhost port=5432 sslmode=disable password='newpass'",
			expectError:        false,
		},
		{
			name:               "DSN string with password",
			inputConnString:    "user=foo password=existingPass dbname=bar host=localhost port=5432 sslmode=disable",
			newPassword:        "newpass",
			expectedConnString: "user=foo password='newpass' dbname=bar host=localhost port=5432 sslmode=disable",
			expectError:        false,
		},
		{
			name:               "DSN string with special characters in password",
			inputConnString:    "user=foo dbname=bar host=localhost port=5432 sslmode=disable",
			newPassword:        "new@pass&special!",
			expectedConnString: "user=foo dbname=bar host=localhost port=5432 sslmode=disable password='new@pass&special!'",
			expectError:        false,
		},
		{
			name:               "DSN string with `'` in new password",
			inputConnString:    "user=foo dbname=bar host=localhost port=5432 sslmode=disable",
			newPassword:        "new'pass",
			expectedConnString: "user=foo dbname=bar host=localhost port=5432 sslmode=disable password='new''pass'",
			expectError:        false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := replaceDBPassword(tc.inputConnString, tc.newPassword)

			if tc.expectError && err == nil {
				t.Errorf("Expected error but got none")
				return
			}

			if !tc.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
				return
			}

			if !tc.expectError {
				if result != tc.expectedConnString {
					t.Errorf("Expected URL: %s, but got: %s", tc.expectedConnString, result)
				}
			}
		})
	}
}

func TestConnectivity(t *testing.T) {
	ctx := context.Background()

	connURL := os.Getenv("PGURL")
	authMethod := os.Getenv("AUTH_METHOD")

	if connURL == "" {
		require.Empty(t, authMethod, "AUTH_METHOD is set but PGURL is not set")

		container, err := prepareTestDBContainer(ctx)
		defer container.Terminate(ctx)

		require.NoError(t, err, "container error")
		require.NotNil(t, container, "container is nil")

		connURL, err = container.ConnectionString(ctx)
		require.NoError(t, err, "reading connection string")
	}

	if authMethod == "aws" {
		require.NotEmpty(t, os.Getenv("AWS_REGION"), "AWS_REGION environment variable is not set")
	}

	config, err := DefaultConfig(ctx, connURL, hclog.NewNullLogger(), DefaultAuthConfigOptions{
		UseAWSIAM:                authMethod == "aws",
		UseAzureMSI:              authMethod == "azure",
		UseGCPDefaultCredentials: authMethod == "gcp",
		AWSDBRegion:              os.Getenv("AWS_REGION"),
		AzureClientID:            os.Getenv("AZURE_CLIENT_ID"),
	})
	require.NoError(t, err, "Failed to create default config")

	err = testConnectivity(t, config)
	require.NoError(t, err, "Failed to test connectivity. authMethod: %s", authMethod)
}

func testConnectivity(t *testing.T, config Config) error {
	t.Log("Testing connectivity to the database")

	ctx := context.Background()
	if err := openTest(ctx, config); err != nil {
		return err
	}

	if err := connectorTest(ctx, config); err != nil {
		return err
	}

	if err := dbPoolTest(ctx, config); err != nil {
		return err
	}

	if err := authenticatedConnStringTest(ctx, config); err != nil {
		return err
	}

	t.Log("All connectivity tests passed")

	return nil
}

func openTest(ctx context.Context, authConfig Config) error {
	db, err := Open(ctx, authConfig)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		return fmt.Errorf("pinging database: %w", err)
	}

	return nil
}

func connectorTest(ctx context.Context, authConfig Config) error {
	connector, err := GetConnector(ctx, authConfig)
	if err != nil {
		return fmt.Errorf("failed to get connector: %w", err)

	}

	db := sql.OpenDB(connector)
	defer db.Close()

	err = db.Ping()
	if err != nil {
		return fmt.Errorf("pinging database: %w", err)
	}

	return nil
}

func dbPoolTest(ctx context.Context, authConfig Config) error {
	pool, err := NewDBPool(ctx, authConfig)
	if err != nil {
		return fmt.Errorf("failed to create pool: %w", err)
	}
	defer pool.Close()

	err = pool.Ping(ctx)
	if err != nil {
		return fmt.Errorf("pinging database: %w", err)
	}

	return nil
}

func authenticatedConnStringTest(ctx context.Context, authConfig Config) error {
	connURL, err := GetAuthenticatedConnString(ctx, authConfig)
	if err != nil {
		return fmt.Errorf("failed to get connection URL: %w", err)
	}

	db, err := sql.Open("pgx", connURL)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()
	err = db.Ping()
	if err != nil {
		return fmt.Errorf("pinging database: %w", err)
	}

	return nil
}

func prepareTestDBContainer(ctx context.Context) (*postgres.PostgresContainer, error) {
	return postgres.Run(ctx, "postgres:14",
		postgres.WithDatabase("hashicorp"),
		postgres.WithUsername("hashicorp"),
		postgres.WithPassword("hashicorp"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(10*time.Second)),
	)
}
