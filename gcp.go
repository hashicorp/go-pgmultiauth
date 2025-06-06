// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pgmultiauth

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type gcpTokenConfig struct {
	creds *google.Credentials
}

func (c gcpTokenConfig) generateToken(ctx context.Context) (*authToken, error) {
	token, err := c.fetchGCPAuthToken()
	if err != nil {
		return nil, fmt.Errorf("fetching gcp token: %v", err)
	}

	validFn := func() bool { return token.Valid() }

	return &authToken{token: token.AccessToken, valid: validFn}, nil
}

func (c gcpTokenConfig) fetchGCPAuthToken() (*oauth2.Token, error) {
	token, err := c.creds.TokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	return token, nil
}

func validateGCPConfig(creds *google.Credentials) error {
	if creds == nil {
		return fmt.Errorf("gcp credentials are required for GCP authentication")
	}

	if creds.TokenSource == nil {
		return fmt.Errorf("gcp token source is required for GCP authentication")
	}

	return nil
}
