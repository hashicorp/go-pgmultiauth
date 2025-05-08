package pgmultiauth

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/avast/retry-go/v4"
	"github.com/aws/aws-sdk-go-v2/aws"
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
	connString string
	logger     hclog.Logger

	// Enum to specify the authentication method
	authMethod AuthMethod

	// AWS Auth
	// Required if authMethod is AWSAuth
	// Region and Credentials must be set in awsConfig
	awsConfig *aws.Config

	// Azure Auth
	// Required if authMethod is AzureAuth
	azureCreds azcore.TokenCredential

	// GCP Auth
	// Required if authMethod is GCPAuth
	googleCreds *google.Credentials
}

// ConfigOpt provides a method to customize a Config.
type ConfigOpt func(r *Config)

// WithLogger overrides the default hclog.Logger.
func WithLogger(l hclog.Logger) ConfigOpt {
	return func(c *Config) {
		c.logger = l
	}
}

// WithawsConfig sets the AWS configuration for the database connection.
func WithAWSConfig(cfg *aws.Config) ConfigOpt {
	return func(c *Config) {
		c.authMethod = AWSAuth
		c.awsConfig = cfg
	}
}

// WithazureCreds sets the Azure credentials for the database connection.
func WithAzureCreds(creds azcore.TokenCredential) ConfigOpt {
	return func(c *Config) {
		c.authMethod = AzureAuth
		c.azureCreds = creds
	}
}

// WithGoogleCreds sets the Google credentials for the database connection.
func WithGoogleCreds(creds *google.Credentials) ConfigOpt {
	return func(c *Config) {
		c.authMethod = GCPAuth
		c.googleCreds = creds
	}
}

// NewConfig creates a new Config with the provided connection string
// and optional configuration options. It sets a null logger
// if no logger is provided.
func NewConfig(connString string, opts ...ConfigOpt) Config {
	cfg := Config{
		connString: connString,

		// Expect logger to be set by the caller via ConfigOpt
		logger: hclog.NewNullLogger(),
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	return cfg
}

// validate checks if the Config has all required fields
// and returns an error if validation fails.
func (c Config) validate() error {
	if c.connString == "" {
		return fmt.Errorf("connString cannot be empty")
	}

	if c.logger == nil {
		return fmt.Errorf("logger cannot be nil")
	}

	// Validate auth-specific configurations
	switch c.authMethod {
	case StandardAuth:
		// No additional validation needed for StandardAuth
	case AWSAuth:
		if err := validateAWSConfig(c.awsConfig); err != nil {
			return fmt.Errorf("invalid AWS config: %v", err)
		}
	case AzureAuth:
		if err := validateAzureConfig(c.azureCreds); err != nil {
			return fmt.Errorf("invalid Azure config: %v", err)
		}
	case GCPAuth:
		if err := validateGCPConfig(c.googleCreds); err != nil {
			return fmt.Errorf("invalid GCP config: %v", err)
		}
	default:
		return fmt.Errorf("unsupported authentication method: %d", c.authMethod)
	}

	return nil
}

// authConfigured checks if any authentication method is configured
func (c Config) authConfigured() bool {
	return c.authMethod != StandardAuth
}

// Open initializes and returns a *sql.DB database connection
// using the provided authentication configuration.
func Open(ctx context.Context, config Config) (*sql.DB, error) {
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("invalid auth configuration: %v", err)
	}

	connConfig, err := pgx.ParseConfig(config.connString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database connection string: %v", err)
	}

	beforeConnect, err := BeforeConnectFn(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("generating before connect function: %v", err)
	}

	db := stdlib.OpenDB(*connConfig, stdlib.OptionBeforeConnect(beforeConnect))
	return db, nil
}

// GetConnector initializes and returns a driver.Connector
// using the provided authentication configuration.
func GetConnector(ctx context.Context, config Config) (driver.Connector, error) {
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("invalid auth configuration: %v", err)
	}

	connConfig, err := pgx.ParseConfig(config.connString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database connection string: %v", err)
	}

	beforeConnect, err := BeforeConnectFn(ctx, config)
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

	connConfig, err := pgxpool.ParseConfig(config.connString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database connection string: %v", err)
	}

	beforeConnect, err := BeforeConnectFn(ctx, config)
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
func BeforeConnectFn(ctx context.Context, config Config) (func(context.Context, *pgx.ConnConfig) error, error) {
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("invalid authentication configuration: %v", err)
	}

	// noop before connect by default
	beforeConnect := func(context.Context, *pgx.ConnConfig) error { return nil }

	if config.authConfigured() {
		config.logger.Info("getting initial db auth token")
		token, err := getAuthTokenWithRetry(ctx, config)
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
				config.logger.Info("refreshing db token")
				token, err = getAuthTokenWithRetry(ctx, config)
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

// GetAuthenticatedConnString returns the database connection string based on the provided
// authentication configuration. It returns the original connection string if no authentication
// method is configured.
func GetAuthenticatedConnString(ctx context.Context, config Config) (string, error) {
	if err := config.validate(); err != nil {
		return "", fmt.Errorf("invalid authentication configuration: %v", err)
	}

	if !config.authConfigured() {
		return config.connString, nil
	}

	token, err := getAuthTokenWithRetry(ctx, config)
	if err != nil {
		return "", fmt.Errorf("fetching auth token: %v", err)
	}

	config.logger.Info("db auth token fetched")

	connString, err := replaceDBPassword(config.connString, token.token)
	if err != nil {
		return "", fmt.Errorf("preparing database connection string with auth token: %v", err)
	}

	return connString, nil
}

// getAuthTokenWithRetry attempts to fetch an authentication token
// with retries in case of failure. It uses exponential backoff
// for retrying the request.
func getAuthTokenWithRetry(ctx context.Context, config Config) (*authToken, error) {
	var token *authToken
	var err error

	err = retry.Do(
		func() error {
			token, err = getAuthToken(ctx, config)
			return err
		},
		retry.Attempts(3),
		retry.Delay(50*time.Millisecond),
		retry.DelayType(retry.BackOffDelay),
		retry.OnRetry(func(n uint, err error) {
			config.logger.Error("failed to fetch auth token", "attempt", n, "error", err)
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
	generateToken(context.Context) (*authToken, error)
}

// getAuthToken returns an authentication token for the database connection
// based on the provided authentication configuration.
func getAuthToken(ctx context.Context, config Config) (*authToken, error) {
	var tokenGenerator tokenGenerator

	switch {
	case config.authMethod == AWSAuth:
		connConfig, err := pgx.ParseConfig(config.connString)
		if err != nil {
			return nil, fmt.Errorf("failed to parse connection string: %v", err)
		}

		tokenGenerator = awsTokenConfig{
			host:      connConfig.Host,
			port:      connConfig.Port,
			user:      connConfig.User,
			awsConfig: config.awsConfig,
		}
	case config.authMethod == GCPAuth:
		tokenGenerator = gcpTokenConfig{
			creds: config.googleCreds,
		}
	case config.authMethod == AzureAuth:
		tokenGenerator = azureTokenConfig{
			creds: config.azureCreds,
		}
	default:
		return nil, fmt.Errorf("unsupported authentication method: %d", config.authMethod)
	}

	return tokenGenerator.generateToken(ctx)
}

// replaceDBPassword replaces the password in a PostgreSQL connection String
// If no password exists in the original string, it adds one
func replaceDBPassword(connString string, newPassword string) (string, error) {
	newConnString := ""

	// connString may be a database URL or in PostgreSQL keyword/value format
	if strings.HasPrefix(connString, "postgres://") || strings.HasPrefix(connString, "postgresql://") {
		var err error
		newConnString, err = replaceDBPasswordURL(connString, newPassword)
		if err != nil {
			return "", fmt.Errorf("preparing database connection url with auth token: %v", err)
		}
	} else {
		newConnString = replaceDBPasswordDSN(connString, newPassword)
	}

	return newConnString, nil
}

func replaceDBPasswordURL(databaseURL, newPassword string) (string, error) {
	u, err := url.Parse(databaseURL)
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

// replaceDBPasswordDSN replaces or adds the password in a PostgreSQL DSN (key=value format).
// It ensures the DSN contains the provided password, replacing any existing password if present.
func replaceDBPasswordDSN(connStr, newPassword string) string {
	// Split the DSN into components
	parts := strings.Split(connStr, " ")
	passwordFound := false
	result := make([]string, 0, len(parts))

	escapedPassword := strings.ReplaceAll(newPassword, "'", "''")

	for _, part := range parts {
		// Check if this part contains the password
		if strings.HasPrefix(part, "password=") {
			result = append(result, fmt.Sprintf("password='%s'", escapedPassword))
			passwordFound = true
		} else {
			result = append(result, part)
		}
	}

	if !passwordFound {
		result = append(result, fmt.Sprintf("password='%s'", escapedPassword))
	}

	return strings.Join(result, " ")
}
