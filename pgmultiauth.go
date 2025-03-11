package pgmultiauth

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"net/url"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

type AuthConfig struct {
	DatabaseURL string
	Logger      hclog.Logger

	// AWS IAM Auth
	UseAWSIAMAuth bool
	AWSDBRegion   string

	// GCP Auth
	UseGCPAuth bool

	// Azure Auth
	UseAzureAuth bool
	ClientID     string
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
	if ac.UseAWSIAMAuth && ac.AWSDBRegion == "" {
		return fmt.Errorf("AWSDBRegion is required when UseAWSIAMAuth is true")
	}

	// Check that only one auth method is selected
	authMethodCount := 0
	if ac.UseAWSIAMAuth {
		authMethodCount++
	}
	if ac.UseGCPAuth {
		authMethodCount++
	}
	if ac.UseAzureAuth {
		authMethodCount++
	}

	if authMethodCount > 1 {
		return fmt.Errorf("only one authentication method can be used at a time")
	}

	return nil
}

// authConfigured checks if any authentication method is configured
func (ac AuthConfig) authConfigured() bool {
	return ac.UseAWSIAMAuth || ac.UseGCPAuth || ac.UseAzureAuth
}

type authToken struct {
	token string
	valid func() bool
}

// DBHandler initializes and returns a *sql.DB database connection
// using the provided authentication configuration.
func DBHandler(authConfig AuthConfig) (*sql.DB, error) {
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

// DBConnector initializes and returns a driver.Connector
// using the provided authentication configuration.
func DBConnector(authConfig AuthConfig) (driver.Connector, error) {
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

// DBPool initializes and returns a *pgxpool.Pool database connection
// using the provided authentication configuration.
func DBPool(ctx context.Context, authConfig AuthConfig) (*pgxpool.Pool, error) {
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

// BeforeConnectFn returns a function that can be used to set the password
// for a database connection before connecting to the database.
func BeforeConnectFn(authConfig AuthConfig) (func(context.Context, *pgx.ConnConfig) error, error) {
	if err := authConfig.validate(); err != nil {
		return nil, fmt.Errorf("invalid authentication configuration: %v", err)
	}

	var beforeConnect func(context.Context, *pgx.ConnConfig) error

	if authConfig.authConfigured() {
		authConfig.Logger.Info("getting initial db auth token")
		token, err := getAuthToken(authConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to get initial db token: %v", err)
		}

		var tokenMutex sync.Mutex

		beforeConnect = func(ctx context.Context, config *pgx.ConnConfig) error {
			tokenMutex.Lock()
			defer tokenMutex.Unlock()

			if !token.valid() {
				authConfig.Logger.Info("refreshing db token")
				token, err = getAuthToken(authConfig)
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

// DatabaseURL returns the database connection URL based on the provided
// authentication configuration.
func DatabaseURL(authConfig AuthConfig) (string, error) {
	if err := authConfig.validate(); err != nil {
		return "", fmt.Errorf("invalid authentication configuration: %v", err)
	}

	if !authConfig.authConfigured() {
		return authConfig.DatabaseURL, nil
	}

	token, err := getAuthToken(authConfig)
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

// getAuthToken returns an authentication token for the database connection
// based on the provided authentication configuration.
func getAuthToken(authConfig AuthConfig) (*authToken, error) {
	connConfig, err := pgx.ParseConfig(authConfig.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection string: %v", err)
	}

	switch {
	case authConfig.UseAWSIAMAuth:
		return getAWSAuthToken(awsTokenConfig{
			host:     connConfig.Host,
			port:     connConfig.Port,
			user:     connConfig.User,
			dbRegion: authConfig.AWSDBRegion,
		}, authConfig.Logger)
	case authConfig.UseGCPAuth:
		return getGCPAuthToken(authConfig.Logger)
	case authConfig.UseAzureAuth:
		return getAzureAuthToken(authConfig.ClientID, authConfig.Logger)
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
