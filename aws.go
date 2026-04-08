// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package pgmultiauth

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type awsTokenConfig struct {
	host      string
	port      uint16
	user      string
	awsConfig *aws.Config
}

func (c awsTokenConfig) generateToken(ctx context.Context) (*authToken, error) {
	token, err := c.fetchAWSAuthToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching aws token: %v", err)
	}

	// The token is valid for 15 minutes, so we set the expiry time to 14 minutes
	// to account for network delays
	expiry := time.Now().Add(14 * time.Minute)
	validFn := func() bool { return time.Now().Before(expiry) }

	return &authToken{token: token, valid: validFn}, nil
}

func (c awsTokenConfig) fetchAWSAuthToken(ctx context.Context) (string, error) {
	creds := c.awsConfig.Credentials
	region := c.awsConfig.Region

	authToken, err := auth.BuildAuthToken(ctx,
		fmt.Sprintf("%s:%d", c.host, c.port),
		region,
		c.user,
		creds,
	)
	if err != nil {
		return "", err
	}

	return authToken, nil
}

func validateAWSConfig(awsConfig *aws.Config) error {
	if awsConfig == nil {
		return fmt.Errorf("aws config is required for AWS authentication")
	}

	if awsConfig.Region == "" {
		return fmt.Errorf("aws region is required for AWS authentication")
	}

	if awsConfig.Credentials == nil {
		return fmt.Errorf("aws credentials are required for AWS authentication")
	}

	return nil
}

// AWSCallerIdentity holds the result of an STS GetCallerIdentity call.
// It is useful for verifying that the AWS credential chain (including IRSA)
// is configured correctly at runtime.
type AWSCallerIdentity struct {
	Account string
	ARN     string
	UserID  string
}

// stsCallerIdentityAPI is the subset of the STS client used by ValidateAWSIdentity.
// Accepting an interface rather than the concrete *sts.Client allows callers to
// inject a mock during testing.
type stsCallerIdentityAPI interface {
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// ValidateAWSIdentity calls STS GetCallerIdentity using the credentials in the
// provided aws.Config. It returns the resolved identity, which is useful for
// verifying that IRSA or another credential source is active.
//
// Example:
//
//	identity, err := pgmultiauth.ValidateAWSIdentity(ctx, cfg)
//	if err != nil { log.Fatal(err) }
//	fmt.Println("Running as", identity.ARN)
func ValidateAWSIdentity(ctx context.Context, cfg *aws.Config) (*AWSCallerIdentity, error) {
	client := sts.NewFromConfig(*cfg)
	return validateAWSIdentityWithClient(ctx, client)
}

func validateAWSIdentityWithClient(ctx context.Context, client stsCallerIdentityAPI) (*AWSCallerIdentity, error) {
	out, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("sts GetCallerIdentity: %w", err)
	}
	return &AWSCallerIdentity{
		Account: aws.ToString(out.Account),
		ARN:     aws.ToString(out.Arn),
		UserID:  aws.ToString(out.UserId),
	}, nil
}
