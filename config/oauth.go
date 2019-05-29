package config

import (
	"github.com/roberveral/oauth-server/jwt"
	"github.com/roberveral/oauth-server/oauth"
	"github.com/roberveral/oauth-server/oauth/idp"
	"github.com/roberveral/oauth-server/oauth/repository/mongodb"
)

// OAuth contains the configuration related to the core OAuth 2 implementation.
type OAuth struct {
	// AccessTokenTTL is the time of expiration of new access tokens, as a duration string.
	// Example: 10s, 3h
	// Default value is 3h
	AccessTokenTTL TTL `default:"3h"`
	// AuthorizationCodeTTL is the time of expiration of new authorization codes, as a duration string.
	// Example: 10s, 3h
	// Default value is 30s
	AuthorizationCodeTTL TTL `default:"30s"`
	// Issuer is the issuer set in access tokens.
	// Default value is: "localhost:8000"
	Issuer string `default:"localhost:8000"`
}

// Manager instantiates a new OAuth manager based on the configuration.
// It uses the given identity provider, store and token provider.
func (c *OAuth) Manager(idp idp.IdentityProvider, store *mongodb.Store, encoder jwt.Encoder) *oauth.Manager {
	return oauth.NewManager(idp, store, encoder, c.Issuer)
}
