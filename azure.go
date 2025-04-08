package pgmultiauth

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

func getAzureAuthToken(clientID string) (*authToken, error) {
	token, err := fetchAzureAuthToken(clientID)
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
		return azcore.AccessToken{}, fmt.Errorf("getting token: %w", err)
	}

	return token, nil
}
