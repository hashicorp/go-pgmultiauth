package main

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-pgmultiauth-beta"
	"golang.org/x/oauth2/google"
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

	var googleCreds *google.Credentials
	var azureCreds azcore.TokenCredential
	var awsConfig *aws.Config

	if authMethod == pgmultiauth.AWSIAMAuth {
		// Get aws region from environment variable
		awsRegion := os.Getenv("AWS_REGION")
		if awsRegion == "" {
			fmt.Println("AWS_REGION is not set")
			return
		}

		awsConfig := &aws.Config{
			Region: aws.String(awsRegion),
		}

		sess, err := session.NewSession(awsConfig)
		if err != nil {
			fmt.Println("failed to create AWS session: %w", err)
			return
		}
		awsConfig.Credentials = sess.Config.Credentials
	} else if authMethod == pgmultiauth.GCPAuth {
		ctx := context.Background()
		creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
		if err != nil {
			fmt.Println("failed to get GCP credentials: %w", err)
			return
		}
		googleCreds = creds
	} else if authMethod == pgmultiauth.AzureAuth {
		// Get Azure client id from environment variable
		azureClientID := os.Getenv("AZURE_CLIENT_ID")

		msiCredOpts := &azidentity.ManagedIdentityCredentialOptions{}
		if azureClientID != "" {
			msiCredOpts.ID = azidentity.ClientID(azureClientID)
		}

		msiCreds, err := azidentity.NewManagedIdentityCredential(msiCredOpts)
		if err != nil {
			fmt.Println("failed to create Azure managed identity credential: %w", err)
			return
		}

		azureCreds = msiCreds
	}

	authConfig := pgmultiauth.AuthConfig{
		DatabaseURL: dbUrl,
		Logger:      hclog.Default(),
		AuthMethod:  authMethod,
		AWSConfig:   awsConfig,
		AzureCreds:  azureCreds,
		GoogleCreds: googleCreds,
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
