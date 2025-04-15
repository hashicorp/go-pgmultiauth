package pgmultiauth

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/hashicorp/go-hclog"
	"golang.org/x/oauth2/google"
)

// CloudAuthConfigOptions holds the configuration options for cloud authentication
// when application is running in a cloud environment.
type CloudAuthConfigOptions struct {
	UseAWSIAM                bool
	UseGCPDefaultCredentials bool
	UseAzureMSI              bool

	// AWS IAM Auth
	AWSDBRegion string

	// Azure MSI Auth
	AzureClientID string
}

// DefaultCloudAuthConfig initializes AuthConfig with default behavior across the clouds. It assumes that application
// is running in a cloud environment and uses the appropriate authentication method based on the provided options.
// For AWS, it uses AWS IAM authentication
// For GCP, it uses GCP default credentials
// For Azure, it uses Managed Identity (MSI) authentication
// For NoAuth, it uses the default PostgreSQL authentication
func DefaultCloudAuthConfig(dbURL string, logger hclog.Logger, opts CloudAuthConfigOptions) (AuthConfig, error) {
	authMode := GetAuthMode(opts.UseAWSIAM, opts.UseGCPDefaultCredentials, opts.UseAzureMSI)

	var googleCreds *google.Credentials
	var azureCreds azcore.TokenCredential
	var awsConfig *aws.Config

	if authMode == AWSAuth {
		if opts.AWSDBRegion == "" {
			return AuthConfig{}, fmt.Errorf("AWSDBRegion is required for AWS IAM authentication")
		}

		sess, err := session.NewSession(&aws.Config{
			Region: aws.String(opts.AWSDBRegion),
		})
		if err != nil {
			return AuthConfig{}, fmt.Errorf("failed to create AWS session: %v", err)
		}

		awsConfig = sess.Config
	} else if authMode == GCPAuth {
		ctx := context.Background()
		creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
		if err != nil {
			return AuthConfig{}, fmt.Errorf("failed to get GCP credentials: %v", err)
		}
		googleCreds = creds
	} else if authMode == AzureAuth {
		msiCredOpts := &azidentity.ManagedIdentityCredentialOptions{}
		if opts.AzureClientID != "" {
			msiCredOpts.ID = azidentity.ClientID(opts.AzureClientID)
		}

		msiCreds, err := azidentity.NewManagedIdentityCredential(msiCredOpts)
		if err != nil {
			return AuthConfig{}, fmt.Errorf("failed to create Azure managed identity credential: %v", err)
		}

		azureCreds = msiCreds
	}

	return AuthConfig{
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
// If none of the flags are set, it returns NoAuth.
func GetAuthMode(useAWSIAMAuth bool, useGCPAuth bool, useAzureAuth bool) AuthMethod {
	switch {
	case useAWSIAMAuth:
		return AWSAuth
	case useGCPAuth:
		return GCPAuth
	case useAzureAuth:
		return AzureAuth
	default:
		return NoAuth
	}
}
