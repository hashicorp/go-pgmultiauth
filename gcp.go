package pgmultiauth

import (
	"fmt"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type gcpTokenConfig struct {
	creds *google.Credentials
}

func (c gcpTokenConfig) generateToken() (*authToken, error) {
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
