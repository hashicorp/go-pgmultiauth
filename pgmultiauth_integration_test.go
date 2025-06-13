// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pgmultiauth

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestConnectivityIntegration(t *testing.T) {
	ctx := context.Background()

	connURL := os.Getenv("PGURL")
	authMethod := os.Getenv("AUTH_METHOD")

	if connURL == "" {
		require.Empty(t, authMethod, "AUTH_METHOD is set but PGURL is not set")

		container, err := prepareTestDBContainer(ctx)
		defer func() {
			if err := container.Terminate(ctx); err != nil {
				t.Logf("Failed to terminate container: %v", err)
			}
		}()

		require.NoError(t, err, "container error")
		require.NotNil(t, container, "container is nil")

		connURL, err = container.ConnectionString(ctx)
		require.NoError(t, err, "reading connection string")
	}

	authMode := StandardAuth
	if authMethod == "aws" {
		authMode = AWSAuth
		require.NotEmpty(t, os.Getenv("AWS_REGION"), "AWS_REGION environment variable is not set")
	} else if authMethod == "gcp" {
		authMode = GCPAuth
	} else if authMethod == "azure" {
		authMode = AzureAuth
	}

	config, err := DefaultConfig(ctx, connURL, DefaultAuthConfigOptions{
		AuthMethod:    authMode,
		AWSDBRegion:   os.Getenv("AWS_REGION"),
		AzureClientID: os.Getenv("AZURE_CLIENT_ID"),
	}, WithLogger(hclog.Default().Named("pgmultiauth_test")))
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
