package pgmultiauth

import (
	"fmt"
	"time"

	"github.com/hashicorp/vault/api"
)

type vaultConfig struct {
	client     *api.Client
	secretPath string
}

func getVaultAuthToken(config vaultConfig) (*authToken, error) {
	secret, err := config.client.Logical().Read(config.secretPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret from vault: %w", err)
	}
	if secret == nil {
		return nil, fmt.Errorf("no secret found at path: %s", config.secretPath)
	}

	password, ok := secret.Data["password"].(string)
	if !ok {
		return nil, fmt.Errorf("failed to get password from secret data")
	}

	username, ok := secret.Data["username"].(string)
	if !ok {
		return nil, fmt.Errorf("failed to get username from secret data")
	}

	// Set expiry to 1 minute before actual expiry to account for network latency
	expiry := time.Now().
		Add(time.Duration(secret.LeaseDuration) * time.Second).
		Add(-1 * time.Minute)

	validFn := func() bool { return time.Now().Before(expiry) }

	return &authToken{username: username, token: password, valid: validFn}, nil
}
