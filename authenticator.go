package unkeyauthenticator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"

	"github.com/portward/registry-auth/auth"
)

var _ auth.PasswordAuthenticator = Authenticator{}

// Authenticator uses [Unkey] to authenticate API keys.
//
// [Unkey]: https://unkey.dev
type Authenticator struct {
	apiID   string
	rootKey string

	url *url.URL

	// TODO: make client configurable
	httpClient *http.Client
}

// NewAuthenticator returns a new [Authenticator].
func NewAuthenticator(apiID string, rootKey string, u *url.URL) Authenticator {
	if u == nil {
		u, _ = url.Parse("https://api.unkey.dev")
	}

	return Authenticator{
		apiID:      apiID,
		rootKey:    rootKey,
		url:        u,
		httpClient: http.DefaultClient,
	}
}

// AuthenticatePassword implements the [auth.PasswordAuthenticator] interface.
func (a Authenticator) AuthenticatePassword(ctx context.Context, username string, password string) (auth.Subject, error) {
	if username != "token" { // TODO: support other usernames
		// TODO: log reason or enrich returned error
		return nil, auth.ErrAuthenticationFailed
	}

	data := map[string]string{
		"key": password,
	}

	var buf bytes.Buffer

	err := json.NewEncoder(&buf).Encode(data)
	if err != nil {
		return nil, err
	}

	u := *a.url
	u.Path = "/v1/keys/verify"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), &buf)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response status: %s", resp.Status)
	}

	var apiResponse verifyKeyResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResponse)
	if err != nil {
		return nil, err
	}

	if !apiResponse.Valid {
		switch apiResponse.Code {
		case "NOT_FOUND", "FORBIDDEN", "KEY_USAGE_EXCEEDED":
			// TODO: add more context to the error
			return nil, auth.ErrAuthenticationFailed

		case "RATELIMITED":
			return nil, errors.New("rate limit error while trying to verify key")

		default:
			return nil, fmt.Errorf("unknown error code: %s", apiResponse.Code)
		}
	}

	if apiResponse.OwnerID == "" {
		return nil, errors.New("owner ID is required")
	}

	return subject{
		id:    auth.SubjectIDFromString(apiResponse.OwnerID),
		attrs: apiResponse.Meta,
	}, nil
}

type verifyKeyResponse struct {
	Valid   bool           `json:"valid"`
	Code    string         `json:"code"`
	OwnerID string         `json:"ownerId"`
	Meta    map[string]any `json:"meta"`

	// TODO: add support for rate limit
}

type subject struct {
	id    auth.SubjectID
	attrs map[string]any
}

// ID implements auth.Subject.
func (s subject) ID() auth.SubjectID {
	return s.id
}

// Attribute implements auth.Subject.
func (s subject) Attribute(key string) (any, bool) {
	v, ok := s.attrs[key]

	return v, ok
}

// Attributes implements auth.Subject.
func (s subject) Attributes() map[string]any {
	return maps.Clone(s.attrs)
}

func (a Authenticator) GetSubjectByID(ctx context.Context, id auth.SubjectID) (auth.Subject, error) {
	query := url.Values{}
	query.Add("ownerId", id.String())

	u := *a.url
	u.Path = fmt.Sprintf("/v1/apis/%s/keys", a.apiID)
	u.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.rootKey))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response status: %s", resp.Status)
	}

	var apiResponse listKeysResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResponse)
	if err != nil {
		return nil, err
	}

	if len(apiResponse.Keys) == 0 {
		// TODO: subject repository should probably return something like SubjectNotFound
		return nil, auth.ErrAuthenticationFailed
	}

	// TODO: maybe check more than just the first key (eg. merge meta, check for expirations)

	return subject{
		id:    id,
		attrs: apiResponse.Keys[0].Meta,
	}, nil
}

type listKeysResponse struct {
	Keys []listKeysKeyItem `json:"keys"`

	// TODO: add support for rate limit
}

type listKeysKeyItem struct {
	Meta map[string]any `json:"meta"`

	// TODO: add support for rate limit
}
