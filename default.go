// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package pgmultiauth

import (
	"context"
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"golang.org/x/oauth2/google"
)

// DefaultAuthConfigOptions holds the configuration options for various authentication
// methods.
type DefaultAuthConfigOptions struct {
	AuthMethod AuthMethod

	// AWS IAM Auth
	AWSDBRegion string

	// AWSRoleARN is the ARN of the IAM role to assume using IRSA
	// (IAM Roles for Service Accounts) on EKS. When empty, falls back
	// to the AWS_ROLE_ARN environment variable.
	AWSRoleARN string

	// AWSWebIdentityTokenFile is the path to the projected service account
	// token used for IRSA authentication on EKS. When empty, falls back
	// to the AWS_WEB_IDENTITY_TOKEN_FILE environment variable.
	AWSWebIdentityTokenFile string

	// ClientID for Azure MSI Auth
	AzureClientID string
}

// DefaultConfig initializes Config with default behavior across the auth methods.
// For Cloud based auth it assumes that application is running in the cloud environment.
// For AWS, it uses AWS IAM authentication
// For GCP, it uses GCP default credentials
// For Azure, it uses Workload Identity or Managed Identity (MSI) authentication
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

		// Configure IRSA (Web Identity Token) credentials when available.
		// On EKS with IRSA, the pod has AWS_ROLE_ARN and AWS_WEB_IDENTITY_TOKEN_FILE
		// environment variables injected by the service account token volume projection.
		roleARN, tokenFile := resolveIRSAConfig(authOpts.AWSRoleARN, authOpts.AWSWebIdentityTokenFile)
		configureIRSACredentials(&cfg, roleARN, tokenFile)

		opts = append(opts, WithAWSAuth(&cfg))
	} else if authOpts.AuthMethod == GCPAuth {
		creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
		if err != nil {
			return Config{}, fmt.Errorf("failed to get GCP credentials: %v", err)
		}

		opts = append(opts, WithGoogleAuth(creds))
	} else if authOpts.AuthMethod == AzureAuth {
		// Use a credential chain to support Workload Identity and Managed Identity.
		var sources []azcore.TokenCredential

		// 1. Workload Identity
		if wiCred, err := azidentity.NewWorkloadIdentityCredential(nil); err == nil {
			sources = append(sources, wiCred)
		}

		// 2. Managed Identity
		msiCredOpts := &azidentity.ManagedIdentityCredentialOptions{}
		if authOpts.AzureClientID != "" {
			msiCredOpts.ID = azidentity.ClientID(authOpts.AzureClientID)
		}
		if msiCred, err := azidentity.NewManagedIdentityCredential(msiCredOpts); err == nil {
			sources = append(sources, msiCred)
		}

		creds, err := azidentity.NewChainedTokenCredential(sources, nil)
		if err != nil {
			return Config{}, fmt.Errorf("failed to create Azure credential: %v", err)
		}

		opts = append(opts, WithAzureAuth(creds))
	}
	cfg := NewConfig(connString, opts...)

	return cfg, nil
}

// resolveIRSAConfig returns the IRSA role ARN and token file path,
// preferring explicit configuration values over environment variables.
func resolveIRSAConfig(roleARN, tokenFile string) (string, string) {
	if roleARN == "" {
		roleARN = os.Getenv("AWS_ROLE_ARN")
	}
	if tokenFile == "" {
		tokenFile = os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE")
	}
	return roleARN, tokenFile
}

// configureIRSACredentials sets up IRSA (Web Identity Token) credentials
// on the AWS config when both role ARN and token file are provided.
func configureIRSACredentials(cfg *aws.Config, roleARN, tokenFile string) {
	if roleARN == "" || tokenFile == "" {
		return
	}
	stsClient := sts.NewFromConfig(*cfg)
	provider := stscreds.NewWebIdentityRoleProvider(
		stsClient,
		roleARN,
		stscreds.IdentityTokenFile(tokenFile),
	)
	cfg.Credentials = aws.NewCredentialsCache(provider)
}
