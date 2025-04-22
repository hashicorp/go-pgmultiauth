package pgmultiauth

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/hashicorp/go-hclog"
	"golang.org/x/oauth2/google"
)

// DefaultAuthConfigOptions holds the configuration options for various authentication
// methods.
type DefaultAuthConfigOptions struct {
	UseAWSIAM                bool
	UseGCPDefaultCredentials bool
	UseAzureMSI              bool

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
func DefaultConfig(ctx context.Context, dbURL string, logger hclog.Logger, opts DefaultAuthConfigOptions) (Config, error) {
	authMode := GetAuthMode(opts.UseAWSIAM, opts.UseGCPDefaultCredentials, opts.UseAzureMSI)

	var googleCreds *google.Credentials
	var azureCreds azcore.TokenCredential
	var awsConfig *aws.Config

	if authMode == AWSAuth {
		if opts.AWSDBRegion == "" {
			return Config{}, fmt.Errorf("AWSDBRegion is required for AWS IAM authentication")
		}

		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(opts.AWSDBRegion))
		if err != nil {
			return Config{}, fmt.Errorf("failed to load AWS config: %v", err)
		}

		awsConfig = &cfg
	} else if authMode == GCPAuth {
		creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
		if err != nil {
			return Config{}, fmt.Errorf("failed to get GCP credentials: %v", err)
		}
		googleCreds = creds
	} else if authMode == AzureAuth {
		msiCredOpts := &azidentity.ManagedIdentityCredentialOptions{}
		if opts.AzureClientID != "" {
			msiCredOpts.ID = azidentity.ClientID(opts.AzureClientID)
		}

		msiCreds, err := azidentity.NewManagedIdentityCredential(msiCredOpts)
		if err != nil {
			return Config{}, fmt.Errorf("failed to create Azure managed identity credential: %v", err)
		}

		azureCreds = msiCreds
	}

	return Config{
		DatabaseURL: dbURL,
		Logger:      logger,
		AuthMethod:  authMode,
		AWSConfig:   awsConfig,
		AzureCreds:  azureCreds,
		GoogleCreds: googleCreds,
	}, nil
}

// GetAuthMode returns the authentication method based on the provided flags.
// It prioritizes AWS IAM authentication, followed by GCP and Azure authentication.
// If none of the flags are set, it returns StandardAuth.
func GetAuthMode(useAWSIAMAuth bool, useGCPAuth bool, useAzureAuth bool) AuthMethod {
	switch {
	case useAWSIAMAuth:
		return AWSAuth
	case useGCPAuth:
		return GCPAuth
	case useAzureAuth:
		return AzureAuth
	default:
		return StandardAuth
	}
}
