package pgmultiauth

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/avast/retry-go/v4"
	"github.com/hashicorp/go-hclog"
)

func getAzureAuthToken(clientID string, logger hclog.Logger) (*authToken, error) {
	var token azcore.AccessToken

	err := retry.Do(
		func() error {
			var err error
			token, err = fetchAzureAuthToken(clientID)
			return err
		},
		retry.Attempts(3),
		retry.Delay(50*time.Millisecond),
		retry.DelayType(retry.BackOffDelay),
		retry.OnRetry(func(n uint, err error) {
			logger.Error("failed to fetch azure token", "attempt", n, "error", err)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("fetching azure token: %v", err)
	}

	// Set expiry to 1 minute before actual expiry to account for network latency
	expiryTime := token.ExpiresOn.Add(-1 * time.Minute)
	validFn := func() bool { return time.Now().Before(expiryTime) }

	return &authToken{token: token.Token, valid: validFn}, nil
}

func fetchAzureAuthToken(clientID string) (azcore.AccessToken, error) {
	msiCredOpts := &azidentity.ManagedIdentityCredentialOptions{}
	if clientID != "" {
		msiCredOpts.ID = azidentity.ClientID(clientID)
	}

	msiCreds, err := azidentity.NewManagedIdentityCredential(msiCredOpts)
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to create Azure managed identity credential (MSI): %w", err)
	}

	ctx := context.Background()
	token, err := msiCreds.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://ossrdbms-aad.database.windows.net/.default"},
	})
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("getting token: %v", err)
	}

	return token, nil
}
