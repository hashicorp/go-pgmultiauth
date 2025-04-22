package pgmultiauth

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

type azureTokenConfig struct {
	creds azcore.TokenCredential
}

func (c azureTokenConfig) generateToken() (*authToken, error) {
	token, err := c.fetchAzureAuthToken()
	if err != nil {
		return nil, fmt.Errorf("fetching azure token: %v", err)
	}

	// Set expiry to 1 minute before actual expiry to account for network latency
	expiryTime := token.ExpiresOn.Add(-1 * time.Minute)
	validFn := func() bool { return time.Now().Before(expiryTime) }

	return &authToken{token: token.Token, valid: validFn}, nil
}

func (c azureTokenConfig) fetchAzureAuthToken() (azcore.AccessToken, error) {
	ctx := context.Background()
	token, err := c.creds.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://ossrdbms-aad.database.windows.net/.default"},
	})
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("getting token: %w", err)
	}

	return token, nil
}

func validateAzureConfig(creds azcore.TokenCredential) error {
	if creds == nil {
		return fmt.Errorf("azure credentials are required for Azure authentication")
	}

	return nil
}
