package main

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-pgmultiauth-beta"
)

func main() {
	fmt.Println("Hello, World!")

	// Get database url from environment varibale
	dbUrl := os.Getenv("DATABASE_URL")
	if dbUrl == "" {
		fmt.Println("DATABASE_URL is not set")
		return
	}

	//Get auth method from environment variable
	authMethod := os.Getenv("AUTH_METHOD")
	if authMethod == "" {
		fmt.Println("AUTH_METHOD is not set")
		return
	}

	//convert to int
	authMethodInt, err := strconv.Atoi(authMethod)
	if err != nil {
		fmt.Println("AUTH_METHOD is not a valid int")
		return
	}

	// Get aws region from environment variable
	awsRegion := os.Getenv("AWS_REGION")

	// Get Azure client id from environment variable
	azureClientID := os.Getenv("AZURE_CLIENT_ID")

	authConfig := pgmultiauth.AuthConfig{
		DatabaseURL:   dbUrl,
		Logger:        hclog.Default(),
		AuthMethod:    pgmultiauth.AuthMethod(authMethodInt),
		AWSDBRegion:   awsRegion,
		AzureClientID: azureClientID,
	}

	db, err := pgmultiauth.Open(authConfig)
	if err != nil {
		fmt.Println("failed to open database: %w", err)
		return
	}

	err = db.Ping()
	if err != nil {
		fmt.Println("pinging database: %w", err)
		return
	}

	// run a query
	const q = `SELECT true`
	var res bool
	err = db.QueryRowContext(context.Background(), q).Scan(&res)
	if err != nil {
		fmt.Println("explicit query: %w", err)
		return
	}

	fmt.Println("Successfully connected to the database")
}
