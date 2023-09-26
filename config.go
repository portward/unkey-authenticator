package unkey

import (
	"fmt"
	"net/url"

	"github.com/portward/registry-auth/auth"
)

// Config implements the [PasswordAuthenticatorFactory] interface defined by Portward.
//
// [PasswordAuthenticatorFactory]: https://pkg.go.dev/github.com/portward/portward/config#PasswordAuthenticatorFactory
type Config struct {
	APIID   string `mapstructure:"apiId"`
	RootKey string `mapstructure:"rootKey"`
	URL     string `mapstructure:"url"`
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

	return NewAuthenticator(c.APIID, c.RootKey, apiURL), nil
}

// Validate validates the configuration.
func (c Config) Validate() error {
	if c.APIID == "" {
		return fmt.Errorf("unkey: API ID is required")
	}

	if c.RootKey == "" {
		return fmt.Errorf("unkey: API ID is required")
	}

	return nil
}
