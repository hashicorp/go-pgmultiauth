// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package pgmultiauth

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
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
