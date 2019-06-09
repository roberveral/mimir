package config

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/roberveral/mimir/jwt"
	"github.com/roberveral/mimir/utils"

	log "github.com/sirupsen/logrus"
)

// JWT contains the configuration related to JWK tokens issued or validated by the server.
type JWT struct {
	// PrivateKeyPath is the path to the RSA Private Key used to sign and decrypt
	// tokens. If it's empty, a random one is generated in the server.
	// Default value is: ''
	PrivateKeyPath string `split_words:"true"`
	// PublicKeyPath is the path to the RSA Public Key used to verify and encrypt
	// tokens (associated with the configured private key).
	// Default value is: ''
	PublicKeyPath string `split_words:"true"`
	// KeyID is the id associated to the public key used to sign JWT tokens. It will
	// be added to the JWT header and returned in the JWK Set endpoint.
	KeyID string
}

// RSAKey instantiates a private key based on the configuration.
func (c *JWT) RSAKey() (*rsa.PrivateKey, error) {
	if c.PrivateKeyPath == "" {
		log.Warn("No private key path set. Using random key")
		return rsa.GenerateKey(rand.Reader, 4096)
	}
	log.Infof("Loading RSA private key from file: %s", c.PrivateKeyPath)
	return utils.LoadRSAPrivateKeyFromFile(c.PrivateKeyPath)
}

// Encoder instantiates a JWT token encoder based on the configuration.
// It uses the given key to sign and verify tokens.
func (c *JWT) Encoder() (jwt.Encoder, error) {
	key, err := c.RSAKey()
	if err != nil {
		return nil, err
	}

	// Generate random key ID if not set
	if c.KeyID == "" {
		c.KeyID = utils.RandString(10)
	}

	log.Infof("Loading JWT Encoder with Key ID: %s", c.KeyID)
	return jwt.NewEncoder(key, c.KeyID)
}
