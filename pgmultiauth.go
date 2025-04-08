package pgmultiauth

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/avast/retry-go/v4"
	"github.com/hashicorp/go-hclog"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

// AuthMethod represents the type of authentication method used
// for connecting to the database.
type AuthMethod int

const (
	NoAuth     AuthMethod = iota // Default value, no authentication
	AWSIAMAuth                   // AWS IAM authentication
	GCPAuth                      // GCP authentication
	AzureAuth                    // Azure authentication
)

// AuthConfig holds the configuration for database authentication.
type AuthConfig struct {
	DatabaseURL string
	Logger      hclog.Logger

	// Enum to specify the authentication method
	AuthMethod AuthMethod

	// AWS IAM Auth
	AWSDBRegion string

	// Azure Auth
	AzureClientID string
}

// validate checks if the AuthConfig has all required fields
// and returns an error if validation fails.
func (ac AuthConfig) validate() error {
	if ac.DatabaseURL == "" {
		return fmt.Errorf("databaseURL cannot be empty")
	}

	if ac.Logger == nil {
		return fmt.Errorf("logger cannot be nil")
	}

	// Validate auth-specific configurations
	switch ac.AuthMethod {
	case NoAuth, GCPAuth:
		// No additional validation needed for NoAuth or GCPAuth
	case AWSIAMAuth:
		if ac.AWSDBRegion == "" {
			return fmt.Errorf("AWSDBRegion is required when AuthMethod is AWSIAMAuth")
		}
	case AzureAuth:
		if ac.AzureClientID == "" {
			return fmt.Errorf("AzureClientID is required when AuthMethod is AzureAuth")
		}
	default:
		return fmt.Errorf("unsupported authentication method: %d", ac.AuthMethod)
	}

	return nil
}

// authConfigured checks if any authentication method is configured
func (ac AuthConfig) authConfigured() bool {
	return ac.AuthMethod != NoAuth
}

type authToken struct {
	token string
	valid func() bool
}

// Open initializes and returns a *sql.DB database connection
// using the provided authentication configuration.
func Open(authConfig AuthConfig) (*sql.DB, error) {
	if err := authConfig.validate(); err != nil {
		return nil, fmt.Errorf("invalid auth configuration: %v", err)
	}

	connConfig, err := pgx.ParseConfig(authConfig.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database connection string: %v", err)
	}

	beforeConnect, err := BeforeConnectFn(authConfig)
	if err != nil {
		return nil, fmt.Errorf("generating before connect function: %v", err)
	}

	db := stdlib.OpenDB(*connConfig, stdlib.OptionBeforeConnect(beforeConnect))
	return db, nil
}

// GetConnector initializes and returns a driver.Connector
// using the provided authentication configuration.
func GetConnector(authConfig AuthConfig) (driver.Connector, error) {
	if err := authConfig.validate(); err != nil {
		return nil, fmt.Errorf("invalid auth configuration: %v", err)
	}

	connConfig, err := pgx.ParseConfig(authConfig.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database connection string: %v", err)
	}

	beforeConnect, err := BeforeConnectFn(authConfig)
	if err != nil {
		return nil, fmt.Errorf("generating before connect function: %v", err)
	}

	return stdlib.GetConnector(*connConfig, stdlib.OptionBeforeConnect(beforeConnect)), nil
}

// NewDBPool initializes and returns a *pgxpool.Pool database connection
// using the provided authentication configuration.
func NewDBPool(ctx context.Context, authConfig AuthConfig) (*pgxpool.Pool, error) {
	if err := authConfig.validate(); err != nil {
		return nil, fmt.Errorf("invalid auth configuration: %v", err)
	}

	connConfig, err := pgxpool.ParseConfig(authConfig.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database connection string: %v", err)
	}

	beforeConnect, err := BeforeConnectFn(authConfig)
	if err != nil {
		return nil, fmt.Errorf("generating before connect function: %v", err)
	}

	connConfig.BeforeConnect = beforeConnect

	// Check if the connection is still valid before acquiring it
	connConfig.BeforeAcquire = func(ctx context.Context, conn *pgx.Conn) bool {
		return conn.Ping(ctx) == nil
	}

	return pgxpool.NewWithConfig(ctx, connConfig)
}

// BeforeConnectFn returns a function that can be used to set up the
// authentication before establishing a connection to the database.
func BeforeConnectFn(authConfig AuthConfig) (func(context.Context, *pgx.ConnConfig) error, error) {
	if err := authConfig.validate(); err != nil {
		return nil, fmt.Errorf("invalid authentication configuration: %v", err)
	}

	var beforeConnect func(context.Context, *pgx.ConnConfig) error

	if authConfig.authConfigured() {
		authConfig.Logger.Info("getting initial db auth token")
		token, err := getAuthTokenWithRetry(authConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to get initial db token: %v", err)
		}

		var tokenMutex sync.Mutex

		beforeConnect = func(ctx context.Context, config *pgx.ConnConfig) error {
			tokenMutex.Lock()
			defer tokenMutex.Unlock()

			if !token.valid() {
				authConfig.Logger.Info("refreshing db token")
				token, err = getAuthTokenWithRetry(authConfig)
				if err != nil {
					return fmt.Errorf("failed to get db token: %v", err)
				}
			}

			config.Password = token.token
			return nil
		}
	}

	return beforeConnect, nil
}

// GetConnectionURL returns the database connection URL based on the provided
// authentication configuration.
func GetConnectionURL(authConfig AuthConfig) (string, error) {
	if err := authConfig.validate(); err != nil {
		return "", fmt.Errorf("invalid authentication configuration: %v", err)
	}

	if !authConfig.authConfigured() {
		return authConfig.DatabaseURL, nil
	}

	token, err := getAuthTokenWithRetry(authConfig)
	if err != nil {
		return "", fmt.Errorf("fetching auth token: %v", err)
	}

	authConfig.Logger.Info("db auth token fetched")

	tokenBasedURL, err := replaceDBPassword(authConfig.DatabaseURL, token.token)
	if err != nil {
		return "", fmt.Errorf("preparing database connection url with auth token: %v", err)
	}

	return tokenBasedURL, nil
}

// GetAuthMode returns the authentication method based on the provided flags.
// It prioritizes AWS IAM authentication, followed by GCP and Azure authentication.
// If none of the flags are set, it returns NoAuth.
func GetAuthMode(useAWSIAMAuth bool, useGCPAuth bool, useAzureAuth bool) AuthMethod {
	switch {
	case useAWSIAMAuth:
		return AWSIAMAuth
	case useGCPAuth:
		return GCPAuth
	case useAzureAuth:
		return AzureAuth
	default:
		return NoAuth
	}
}

// getAuthTokenWithRetry attempts to fetch an authentication token
// with retries in case of failure. It uses exponential backoff
// for retrying the request.
func getAuthTokenWithRetry(authConfig AuthConfig) (*authToken, error) {
	var token *authToken
	var err error

	err = retry.Do(
		func() error {
			token, err = getAuthToken(authConfig)
			return err
		},
		retry.Attempts(3),
		retry.Delay(50*time.Millisecond),
		retry.DelayType(retry.BackOffDelay),
		retry.OnRetry(func(n uint, err error) {
			authConfig.Logger.Error("failed to fetch auth token", "attempt", n, "error", err)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("fetching auth token: %v", err)
	}

	return token, nil
}

// getAuthToken returns an authentication token for the database connection
// based on the provided authentication configuration.
func getAuthToken(authConfig AuthConfig) (*authToken, error) {
	connConfig, err := pgx.ParseConfig(authConfig.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection string: %v", err)
	}

	switch {
	case authConfig.AuthMethod == AWSIAMAuth:
		return getAWSAuthToken(awsTokenConfig{
			host:     connConfig.Host,
			port:     connConfig.Port,
			user:     connConfig.User,
			dbRegion: authConfig.AWSDBRegion,
		})
	case authConfig.AuthMethod == GCPAuth:
		return getGCPAuthToken()
	case authConfig.AuthMethod == AzureAuth:
		return getAzureAuthToken(authConfig.AzureClientID)
	default:
		return nil, fmt.Errorf("unsupported authentication method")
	}
}

// replaceDBPassword replaces the password in a PostgreSQL connection URL
// If no password exists in the original URL, it adds one
func replaceDBPassword(connectionURL string, newPassword string) (string, error) {
	u, err := url.Parse(connectionURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse connection URL: %w", err)
	}

	dbURL := fmt.Sprintf("%s://%s:%s@%s%s",
		u.Scheme,
		url.QueryEscape(u.User.Username()),
		url.QueryEscape(newPassword),
		u.Host,
		u.Path,
	)

	if u.RawQuery != "" {
		dbURL = fmt.Sprintf("%s?%s", dbURL, u.RawQuery)
	}

	if u.Fragment != "" {
		dbURL = fmt.Sprintf("%s#%s", dbURL, u.Fragment)
	}

	return dbURL, nil
}
