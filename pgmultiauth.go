package pgmultiauth

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/avast/retry-go/v4"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/hashicorp/go-hclog"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/oauth2/google"
)

// AuthMethod represents the type of authentication method used
// for connecting to the database.
type AuthMethod int

const (
	StandardAuth AuthMethod = iota // Default value, standard authentication
	AWSAuth                        // AWS authentication
	GCPAuth                        // GCP authentication
	AzureAuth                      // Azure authentication
)

// Config holds the configuration for the database.
type Config struct {
	DatabaseURL string
	Logger      hclog.Logger

	// Enum to specify the authentication method
	AuthMethod AuthMethod

	// AWS Auth
	// Required if AuthMethod is AWSAuth
	// Region and Credentials must be set in AWSConfig
	AWSConfig *aws.Config

	// Azure Auth
	// Required if AuthMethod is AzureAuth
	AzureCreds azcore.TokenCredential

	// GCP Auth
	// Required if AuthMethod is GCPAuth
	GoogleCreds *google.Credentials
}

// validate checks if the Config has all required fields
// and returns an error if validation fails.
func (c Config) validate() error {
	if c.DatabaseURL == "" {
		return fmt.Errorf("databaseURL cannot be empty")
	}

	if c.Logger == nil {
		return fmt.Errorf("logger cannot be nil")
	}

	// Validate auth-specific configurations
	switch c.AuthMethod {
	case StandardAuth:
		// No additional validation needed for StandardAuth
	case AWSAuth:
		if err := validateAWSConfig(c.AWSConfig); err != nil {
			return fmt.Errorf("invalid AWS config: %v", err)
		}
	case AzureAuth:
		if err := validateAzureConfig(c.AzureCreds); err != nil {
			return fmt.Errorf("invalid Azure config: %v", err)
		}
	case GCPAuth:
		if err := validateGCPConfig(c.GoogleCreds); err != nil {
			return fmt.Errorf("invalid GCP config: %v", err)
		}
	default:
		return fmt.Errorf("unsupported authentication method: %d", c.AuthMethod)
	}

	return nil
}

// authConfigured checks if any authentication method is configured
func (c Config) authConfigured() bool {
	return c.AuthMethod != StandardAuth
}

// Open initializes and returns a *sql.DB database connection
// using the provided authentication configuration.
func Open(config Config) (*sql.DB, error) {
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("invalid auth configuration: %v", err)
	}

	connConfig, err := pgx.ParseConfig(config.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database connection string: %v", err)
	}

	beforeConnect, err := BeforeConnectFn(config)
	if err != nil {
		return nil, fmt.Errorf("generating before connect function: %v", err)
	}

	db := stdlib.OpenDB(*connConfig, stdlib.OptionBeforeConnect(beforeConnect))
	return db, nil
}

// GetConnector initializes and returns a driver.Connector
// using the provided authentication configuration.
func GetConnector(config Config) (driver.Connector, error) {
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("invalid auth configuration: %v", err)
	}

	connConfig, err := pgx.ParseConfig(config.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database connection string: %v", err)
	}

	beforeConnect, err := BeforeConnectFn(config)
	if err != nil {
		return nil, fmt.Errorf("generating before connect function: %v", err)
	}

	return stdlib.GetConnector(*connConfig, stdlib.OptionBeforeConnect(beforeConnect)), nil
}

// NewDBPool initializes and returns a *pgxpool.Pool database connection
// using the provided authentication configuration.
func NewDBPool(ctx context.Context, config Config) (*pgxpool.Pool, error) {
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("invalid auth configuration: %v", err)
	}

	connConfig, err := pgxpool.ParseConfig(config.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database connection string: %v", err)
	}

	beforeConnect, err := BeforeConnectFn(config)
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
func BeforeConnectFn(config Config) (func(context.Context, *pgx.ConnConfig) error, error) {
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("invalid authentication configuration: %v", err)
	}

	// noop before connect by default
	beforeConnect := func(context.Context, *pgx.ConnConfig) error { return nil }

	if config.authConfigured() {
		config.Logger.Info("getting initial db auth token")
		token, err := getAuthTokenWithRetry(config)
		if err != nil {
			return nil, fmt.Errorf("failed to get initial db token: %v", err)
		}

		var tokenMutex sync.Mutex

		beforeConnect = func(ctx context.Context, connConfig *pgx.ConnConfig) error {
			// no point in contending for lock if we know the token is valid
			if token.valid() {
				connConfig.Password = token.token
				return nil
			}

			// acquire lock if token is not valid
			tokenMutex.Lock()
			defer tokenMutex.Unlock()

			// necessary because multiple connections in the pool might be waiting to acquire tokenMutex after finding the token invalid
			// and the token might have been refreshed by a connection that acquired the lock first
			if !token.valid() {
				config.Logger.Info("refreshing db token")
				token, err = getAuthTokenWithRetry(config)
				if err != nil {
					return fmt.Errorf("failed to get db token: %v", err)
				}
			}

			connConfig.Password = token.token
			return nil
		}
	}

	return beforeConnect, nil
}

// GetConnectionURL returns the database connection URL based on the provided
// authentication configuration.
func GetConnectionURL(config Config) (string, error) {
	if err := config.validate(); err != nil {
		return "", fmt.Errorf("invalid authentication configuration: %v", err)
	}

	if !config.authConfigured() {
		return config.DatabaseURL, nil
	}

	token, err := getAuthTokenWithRetry(config)
	if err != nil {
		return "", fmt.Errorf("fetching auth token: %v", err)
	}

	config.Logger.Info("db auth token fetched")

	tokenBasedURL, err := replaceDBPassword(config.DatabaseURL, token.token)
	if err != nil {
		return "", fmt.Errorf("preparing database connection url with auth token: %v", err)
	}

	return tokenBasedURL, nil
}

// getAuthTokenWithRetry attempts to fetch an authentication token
// with retries in case of failure. It uses exponential backoff
// for retrying the request.
func getAuthTokenWithRetry(config Config) (*authToken, error) {
	var token *authToken
	var err error

	err = retry.Do(
		func() error {
			token, err = getAuthToken(config)
			return err
		},
		retry.Attempts(3),
		retry.Delay(50*time.Millisecond),
		retry.DelayType(retry.BackOffDelay),
		retry.OnRetry(func(n uint, err error) {
			config.Logger.Error("failed to fetch auth token", "attempt", n, "error", err)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("fetching auth token: %v", err)
	}

	return token, nil
}

type authToken struct {
	token string
	valid func() bool
}

// tokenGenerator is an interface that defines a method for generating
// authentication tokens. This allows for different implementations
// for different authentication methods (AWS, GCP, Azure).
type tokenGenerator interface {
	generateToken() (*authToken, error)
}

// getAuthToken returns an authentication token for the database connection
// based on the provided authentication configuration.
func getAuthToken(config Config) (*authToken, error) {
	var tokenGenerator tokenGenerator

	switch {
	case config.AuthMethod == AWSAuth:
		connConfig, err := pgx.ParseConfig(config.DatabaseURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse connection string: %v", err)
		}

		tokenGenerator = awsTokenConfig{
			host:      connConfig.Host,
			port:      connConfig.Port,
			user:      connConfig.User,
			awsConfig: config.AWSConfig,
		}
	case config.AuthMethod == GCPAuth:
		tokenGenerator = gcpTokenConfig{
			creds: config.GoogleCreds,
		}
	case config.AuthMethod == AzureAuth:
		tokenGenerator = azureTokenConfig{
			creds: config.AzureCreds,
		}
	default:
		return nil, fmt.Errorf("unsupported authentication method: %d", config.AuthMethod)
	}

	return tokenGenerator.generateToken()
}

// replaceDBPassword replaces the password in a PostgreSQL connection URL
// If no password exists in the original URL, it adds one
func replaceDBPassword(connectionURL string, newPassword string) (string, error) {
	u, err := url.Parse(connectionURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse connection URL: %w", err)
	}

	var username string
	if u.User != nil {
		username = u.User.Username()
	}

	dbURL := fmt.Sprintf("%s://%s:%s@%s%s",
		u.Scheme,
		url.QueryEscape(username),
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
