package pgmultiauth

import (
	"fmt"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func getGCPAuthToken(creds *google.Credentials) (*authToken, error) {
	token, err := fetchGCPAuthToken(creds)
	if err != nil {
		return nil, fmt.Errorf("fetching gcp token: %v", err)
	}

	validFn := func() bool { return token.Valid() }

	return &authToken{token: token.AccessToken, valid: validFn}, nil
}

func fetchGCPAuthToken(creds *google.Credentials) (*oauth2.Token, error) {
	token, err := creds.TokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	return token, nil
}
