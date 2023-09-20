package unkeyauthenticator

import (
	"context"
	"os"
	"testing"

	"github.com/portward/registry-auth/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO: create API keys on the fly OR run unkey locally
func TestAuthenticator(t *testing.T) {
	apiKey := os.Getenv("UNKEY_APIKEY")

	if apiKey == "" {
		t.Skip("API key is not configured")
	}

	authenticator := NewAuthenticator(nil)

	subject, err := authenticator.AuthenticatePassword(context.Background(), "token", apiKey)
	require.NoError(t, err)

	expectedID := auth.SubjectIDFromString("id")
	expectedMeta := map[string]any{
		"group": "admin",
		"roles": []any{"user", "admin"},
	}

	assert.True(t, subject.ID().Equals(expectedID))
	assert.Equal(t, expectedMeta, subject.Attributes())
}
