package config

import (
	"fmt"

	"github.com/roberveral/oauth-server/jwt"
	"github.com/roberveral/oauth-server/oauth"
	"github.com/roberveral/oauth-server/oauth/idp"
	"github.com/roberveral/oauth-server/oauth/model"
	"github.com/roberveral/oauth-server/oauth/repository/mongodb"
	"github.com/roberveral/oauth-server/openid"
	"gopkg.in/square/go-jose.v2"
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
	Issuer string `default:"http://localhost:8000"`
	// ScopesSupported is the list of OAuth scopes that the server supports,
	// without including the OpenID related ones.
	ScopesSupported []string `default:""`
}

// Manager instantiates a new OAuth manager based on the configuration.
// It uses the given identity provider, store and token provider.
func (c *OAuth) Manager(idp idp.IdentityProvider, store *mongodb.Store, encoder jwt.Encoder) *oauth.Manager {
	providerMetadata := &openid.ProviderMetadata{
		Issuer:                            c.Issuer,
		AuthorizationEndpoint:             fmt.Sprintf("%s/v0/oauth/authorize", c.Issuer),
		TokenEndpoint:                     fmt.Sprintf("%s/v0/oauth/token", c.Issuer),
		UserInfoEndpoint:                  fmt.Sprintf("%s/v0/openid/userinfo", c.Issuer),
		JwksURI:                           fmt.Sprintf("%s/.well-known/jwks.json", c.Issuer),
		RegistrationEndpoint:              fmt.Sprintf("%s/v0/clients", c.Issuer),
		ScopesSupported:                   append(c.ScopesSupported, openid.OpenIDScope, openid.ProfileScope, openid.EmailScope),
		ResponseTypesSupported:            []string{string(model.CodeResponseType)},
		GrantTypesSupported:               []string{string(model.AuthorizationCodeGrantType), string(model.PasswordGrantType), string(model.ClientCredentialsGrantType)},
		IDTokenSigningAlgValuesSupported:  []string{string(jose.RS256)},
		TokenEndpointAuthMethodsSupported: []string{openid.ClientSecretPostTokenAuthMethod},
		CodeChallengeMethodsSupported:     []string{string(model.PlainCodeChallengeMethod), string(model.S256CodeChallengeMethod)},
	}
	return oauth.NewManager(idp, store, encoder, providerMetadata)
}
