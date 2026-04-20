// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package pgmultiauth

import (
	"context"
	"fmt"
	"os"

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

	// ClientID for Azure user-assigned managed identity when workload identity
	// environment variables are not present.
	AzureClientID string
}

// DefaultConfig initializes Config with default behavior across the auth methods.
// For Cloud based auth it assumes that application is running in the cloud environment.
// For AWS, it uses AWS IAM authentication
// For GCP, it uses GCP default credentials
// For Azure, it uses DefaultAzureCredential, which supports workload identity,
// managed identity, and local developer credentials.
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

		opts = append(opts, WithAWSAuth(&cfg))
	} else if authOpts.AuthMethod == GCPAuth {
		creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
		if err != nil {
			return Config{}, fmt.Errorf("failed to get GCP credentials: %v", err)
		}

		opts = append(opts, WithGoogleAuth(creds))
	} else if authOpts.AuthMethod == AzureAuth {
		prepareAzureDefaultCredentialEnv(authOpts)

		creds, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return Config{}, fmt.Errorf("failed to create Azure credential: %v", err)
		}

		opts = append(opts, WithAzureAuth(creds))
	}
	cfg := NewConfig(connString, opts...)

	return cfg, nil
}

func prepareAzureDefaultCredentialEnv(authOpts DefaultAuthConfigOptions) {
	if authOpts.AzureClientID == "" {
		return
	}

	_, hasFederatedTokenFile := os.LookupEnv("AZURE_FEDERATED_TOKEN_FILE")
	_, hasTenantID := os.LookupEnv("AZURE_TENANT_ID")
	if hasFederatedTokenFile || hasTenantID {
		return
	}

	_ = os.Setenv("AZURE_CLIENT_ID", authOpts.AzureClientID)
}
