// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package pgmultiauth

import (
	"context"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// MockTokenCredential is a mock implementation of azcore.TokenCredential
type MockTokenCredential struct {
	Token  string
	Expiry time.Time
}

// GetToken implements the azcore.TokenCredential interface
func (m *MockTokenCredential) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{
		Token:     m.Token,
		ExpiresOn: m.Expiry,
	}, nil
}
