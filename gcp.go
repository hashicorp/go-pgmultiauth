package pgmultiauth

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func getGCPAuthToken() (*authToken, error) {
	token, err := fetchGCPAuthToken()
	if err != nil {
		return nil, fmt.Errorf("fetching gcp token: %v", err)
	}

	validFn := func() bool { return token.Valid() }

	return &authToken{token: token.AccessToken, valid: validFn}, nil
}

func fetchGCPAuthToken() (*oauth2.Token, error) {
	ctx := context.Background()
	creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}

	token, err := creds.TokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	return token, nil
}
