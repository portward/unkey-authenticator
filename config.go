package unkeyauthenticator

import (
	"net/url"

	"github.com/portward/registry-auth/auth"
)

// Config implements the [PasswordAuthenticatorFactory] interface defined by Portward.
//
// [PasswordAuthenticatorFactory]: https://pkg.go.dev/github.com/portward/portward/config#PasswordAuthenticatorFactory
type Config struct {
	URL string `mapstructure:"url"`
}

// New returns a new [Authenticator] from the configuration.
func (c Config) New() (auth.PasswordAuthenticator, error) {
	u := c.URL
	if c.URL == "" {
		u = "https://api.unkey.dev"
	}

	apiURL, err := url.Parse(u)
	if err != nil { // TODO: valdate URL (if present)
		return nil, err
	}

	return NewAuthenticator(apiURL), nil
}

// Validate validates the configuration.
func (c Config) Validate() error {
	return nil
}
