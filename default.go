package pgmultiauth

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/aws/aws-sdk-go-v2/config"
	"golang.org/x/oauth2/google"
)

// DefaultAuthConfigOptions holds the configuration options for various authentication
// methods.
type DefaultAuthConfigOptions struct {
	AuthMethod AuthMethod

	// AWS IAM Auth
	AWSDBRegion string

	// Azure MSI Auth
	AzureClientID string
}

// DefaultConfig initializes Config with default behavior across the auth methods.
// For Cloud based auth it assumes that application is running in the cloud environment.
// For AWS, it uses AWS IAM authentication
// For GCP, it uses GCP default credentials
// For Azure, it uses Managed Identity (MSI) authentication
// For StandardAuth, it uses the default PostgreSQL authentication
func DefaultConfig(ctx context.Context, connString string, authOpts DefaultAuthConfigOptions, opts ...ConfigOpt) (Config, error) {
	if authOpts.AuthMethod == AWSAuth {
		if authOpts.AWSDBRegion == "" {
			return Config{}, fmt.Errorf("AWSDBRegion is required for AWS IAM authentication")
		}

		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(authOpts.AWSDBRegion))
		if err != nil {
			return Config{}, fmt.Errorf("failed to load AWS config: %v", err)
		}

		opts = append(opts, WithAWSConfig(&cfg))
	} else if authOpts.AuthMethod == GCPAuth {
		creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
		if err != nil {
			return Config{}, fmt.Errorf("failed to get GCP credentials: %v", err)
		}

		opts = append(opts, WithGoogleCreds(creds))
	} else if authOpts.AuthMethod == AzureAuth {
		msiCredOpts := &azidentity.ManagedIdentityCredentialOptions{}
		if authOpts.AzureClientID != "" {
			msiCredOpts.ID = azidentity.ClientID(authOpts.AzureClientID)
		}

		msiCreds, err := azidentity.NewManagedIdentityCredential(msiCredOpts)
		if err != nil {
			return Config{}, fmt.Errorf("failed to create Azure managed identity credential: %v", err)
		}

		opts = append(opts, WithAzureCreds(msiCreds))
	}
	cfg := NewConfig(connString, opts...)

	return cfg, nil
}
