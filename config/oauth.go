package config

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/roberveral/oauth-server/oauth"
	"github.com/roberveral/oauth-server/oauth/idp"
	"github.com/roberveral/oauth-server/oauth/repository/mongodb"
	"github.com/roberveral/oauth-server/oauth/token/jwt"
	"github.com/roberveral/oauth-server/utils"

	log "github.com/sirupsen/logrus"
)

// OAuth contains the configuration related to the core OAuth 2 implementation.
type OAuth struct {
	// PrivateKeyPath is the path to the RSA Private Key used to sign and decrypt
	// tokens. If it's empty, a random one is generated in the server.
	// Default value is: ''
	PrivateKeyPath string `split_words:"true"`
	// PublicKeyPath is the path to the RSA Public Key used to verify and encrypt
	// tokens (associated with the configured private key).
	// Default value is: ''
	PublicKeyPath string `split_words:"true"`
	// AccessTokenTTL is the time of expiration of new access tokens, as a duration string.
	// Example: 10s, 3h
	// Default value is 3h
	AccessTokenTTL TTL `default:"3h"`
	// AuthorizationCodeTTL is the time of expiration of new authorization codes, as a duration string.
	// Example: 10s, 3h
	// Default value is 30s
	AuthorizationCodeTTL TTL `default:"30s"`
	// Issuer is the issuer set in access tokens.
	// Default value is: "oauth-server"
	Issuer string `default:"oauth-server"`
}

// RSAKey instantiates a private key based on the configuration.
func (c *OAuth) RSAKey() (*rsa.PrivateKey, error) {
	if c.PrivateKeyPath == "" {
		log.Warn("No private key path set. Using random key")
		return rsa.GenerateKey(rand.Reader, 4096)
	}
	log.Infof("Loading RSA private key from file: %s", c.PrivateKeyPath)
	return utils.LoadRSAPrivateKeyFromFile(c.PrivateKeyPath)
}

// TokenProvider instantiates a JWT token provider based on the configuration.
// It uses the given key to sign and verify tokens.
func (c *OAuth) TokenProvider(key *rsa.PrivateKey) (*jwt.TokenProvider, error) {
	return jwt.New(key)
}

// Manager instantiates a new OAuth manager based on the configuration.
// It uses the given identity provider, store and token provider.
func (c *OAuth) Manager(idp idp.IdentityProvider, store *mongodb.Store, token *jwt.TokenProvider) *oauth.Manager {
	return oauth.NewManager(idp, store, token)
}
