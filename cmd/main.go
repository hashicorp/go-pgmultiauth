package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-pgmultiauth"
)

func main() {
	fmt.Println("Hello, \n1 -- 2 --- 3. \nTesting startttt!!!!")

	// Get database url from environment varibale
	dbUrl := os.Getenv("DATABASE_URL")
	if dbUrl == "" {
		fmt.Println("DATABASE_URL is not set")
		return
	}

	//Get auth method from environment variable
	authMethodEnv := os.Getenv("AUTH_METHOD")
	if authMethodEnv == "" {
		fmt.Println("AUTH_METHOD is not set")
		return
	}

	//convert to int
	authMethodInt, err := strconv.Atoi(authMethodEnv)
	if err != nil {
		fmt.Println("AUTH_METHOD is not a valid int")
		return
	}

	authMethod := pgmultiauth.AuthMethod(authMethodInt)

	useAWSIAMAuth := authMethod == pgmultiauth.AWSAuth
	useGCPAuth := authMethod == pgmultiauth.GCPAuth
	useAzureAuth := authMethod == pgmultiauth.AzureAuth

	ctx := context.Background()

	authConfig, err := pgmultiauth.DefaultConfig(ctx, dbUrl, hclog.Default(), pgmultiauth.DefaultAuthConfigOptions{
		UseAWSIAM:   useAWSIAMAuth,
		AWSDBRegion: os.Getenv("AWS_REGION"),

		UseGCPDefaultCredentials: useGCPAuth,

		UseAzureMSI:   useAzureAuth,
		AzureClientID: os.Getenv("AZURE_CLIENT_ID"),
	})
	if err != nil {
		fmt.Println("failed to create auth config:", err)
		return
	}

	openTest(ctx, authConfig)
	connectorTest(ctx, authConfig)
	dbPoolTest(ctx, authConfig)
	connectionURLTest(ctx, authConfig)
}

func openTest(ctx context.Context, authConfig pgmultiauth.Config) {
	db, err := pgmultiauth.Open(ctx, authConfig)
	if err != nil {
		fmt.Println("failed to open database: %w", err)
		return
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		fmt.Println("pinging database: %w", err)
		return
	}

	fmt.Println("Successfully connected to the database using Open")
}

func connectorTest(ctx context.Context, authConfig pgmultiauth.Config) {
	connector, err := pgmultiauth.GetConnector(ctx, authConfig)
	if err != nil {
		fmt.Println("failed to get connector: %w", err)
		return
	}

	db := sql.OpenDB(connector)
	defer db.Close()

	err = db.Ping()
	if err != nil {
		fmt.Println("pinging database: %w", err)
		return
	}

	fmt.Println("Successfully connected to the database using connector")
}

func dbPoolTest(ctx context.Context, authConfig pgmultiauth.Config) {
	pool, err := pgmultiauth.NewDBPool(ctx, authConfig)
	if err != nil {
		fmt.Println("failed to create pool: %w", err)
		return
	}
	defer pool.Close()

	err = pool.Ping(ctx)
	if err != nil {
		fmt.Println("pinging database: %w", err)
		return
	}

	fmt.Println("Successfully connected to the database using pool")
}

func connectionURLTest(ctx context.Context, authConfig pgmultiauth.Config) {
	connURL, err := pgmultiauth.GetAuthenticatedConnString(ctx, authConfig)
	if err != nil {
		fmt.Println("failed to get connection URL: %w", err)
		return
	}

	db, err := sql.Open("pgx", connURL)
	if err != nil {
		fmt.Println("failed to open database: %w", err)
		return
	}
	defer db.Close()
	err = db.Ping()
	if err != nil {
		fmt.Println("pinging database: %w", err)
		return
	}

	fmt.Println("Successfully connected to the database using connection URL")
}
