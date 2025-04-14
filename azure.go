package pgmultiauth

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

func getAzureAuthToken(azureCreds azcore.TokenCredential) (*authToken, error) {
	token, err := fetchAzureAuthToken(azureCreds)
	if err != nil {
		return nil, fmt.Errorf("fetching azure token: %v", err)
	}

	// Set expiry to 1 minute before actual expiry to account for network latency
	expiryTime := token.ExpiresOn.Add(-1 * time.Minute)
	validFn := func() bool { return time.Now().Before(expiryTime) }

	return &authToken{token: token.Token, valid: validFn}, nil
}

func fetchAzureAuthToken(azureCreds azcore.TokenCredential) (azcore.AccessToken, error) {
	ctx := context.Background()
	token, err := azureCreds.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://ossrdbms-aad.database.windows.net/.default"},
	})
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("getting token: %w", err)
	}

	return token, nil
}
