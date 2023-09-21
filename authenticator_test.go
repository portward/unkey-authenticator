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
	apiID := os.Getenv("UNKEY_API_ID")
	rootKey := os.Getenv("UNKEY_ROOT_KEY")
	apiKey := os.Getenv("UNKEY_API_KEY")

	if apiID == "" {
		t.Skip("API ID is not configured")
	}

	if rootKey == "" {
		t.Skip("root key is not configured")
	}

	if apiKey == "" {
		t.Skip("API key is not configured")
	}

	authenticator := NewAuthenticator(apiID, rootKey, nil)

	t.Run("PasswordAuthenticator", func(t *testing.T) {
		subject, err := authenticator.AuthenticatePassword(context.Background(), "token", apiKey)
		require.NoError(t, err)

		expectedID := auth.SubjectIDFromString("id")
		expectedMeta := map[string]any{
			"group": "admin",
			"roles": []any{"user", "admin"},
		}

		assert.True(t, subject.ID().Equals(expectedID))
		assert.Equal(t, expectedMeta, subject.Attributes())
	})

	t.Run("SubjectRepository", func(t *testing.T) {
		subjectID := auth.SubjectIDFromString("id")

		subject, err := authenticator.GetSubjectByID(context.Background(), subjectID)
		require.NoError(t, err)

		expectedMeta := map[string]any{
			"group": "admin",
			"roles": []any{"user", "admin"},
		}

		assert.True(t, subject.ID().Equals(subjectID))
		assert.Equal(t, expectedMeta, subject.Attributes())
	})
}
