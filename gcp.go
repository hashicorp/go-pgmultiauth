package pgmultiauth

import (
	"context"
	"fmt"
	"time"

	"github.com/avast/retry-go/v4"
	"github.com/hashicorp/go-hclog"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func getGCPAuthToken(logger hclog.Logger) (*authToken, error) {
	var token *oauth2.Token

	err := retry.Do(
		func() error {
			var err error
			token, err = fetchGCPAuthToken()
			return err
		},
		retry.Attempts(3),
		retry.Delay(50*time.Millisecond),
		retry.DelayType(retry.BackOffDelay),
		retry.OnRetry(func(n uint, err error) {
			logger.Error("failed to fetch gcp token", "attempt", n, "error", err)
		}),
	)
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
