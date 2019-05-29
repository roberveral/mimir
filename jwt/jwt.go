package jwt

import (
	"crypto/rsa"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// Encoder is an interface which contains the methods to encode and decode JWT tokens
// given the token claims. It allows to abstract from the details of cryptography, focusing
// only in the token contents.
type Encoder interface {
	// Signed encodes a new JWT token which is signed according to the JWS specification and
	// contains the given claims.
	// The algorithm and key used is left to implementations.
	Signed(claims interface{}) (string, error)

	// Encrypted encodes a new JWT token which is signed and encrypted according to the JWS and
	// JWE specifications, containing the given claims.
	// The algorithm and key used is left to implementations.
	Encrypted(claims interface{}) (string, error)

	// ValidateSigned decodes the given JWT signed token. It validates the signature, checks that
	// it has not expired and parses the claims into the given destination.
	// Tokens are expected with the same algorithm than the Signed method.
	ValidateSigned(token string, dest interface{}) error

	// ValidateEncrypted decodes the given JWT signed and encrypted token. It validates the signature,
	// checks that it has not expired and parses the claims into the given destination.
	// Tokens are expected with the same algorithm than the Encrypted method.
	ValidateEncrypted(token string, dest interface{}) error

	// JWKS obtains the JWK Set definition of the public key used by the encoder to sign tokens,
	// so other services can validate the token signature.
	JWKS() *jose.JSONWebKeySet
}

type jwtEncoder struct {
	PrivateKey *rsa.PrivateKey
	KeyID      string
	encrypter  jose.Encrypter
	signer     jose.Signer
}

// NewEncoder creates a new Encoder which uses the given RSA private key to sign and encrypt
// tokens, using the RS512 and RSA_OAEP algorithms.
func NewEncoder(privateKey *rsa.PrivateKey, keyID string) (Encoder, error) {
	encoder := &jwtEncoder{
		PrivateKey: privateKey,
		KeyID:      keyID,
	}

	// Signer used to sign JWT tokens. Using RS512 algorithm so the Authorization Server
	// signs each token with its private key and Resource Servers can validate the token
	// signature using the Authorization Server's public key.
	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.RS512,
			Key:       encoder.privateKeyJWKSig(),
		},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return nil, err
	}

	encoder.signer = signer

	// Encrypter used to encrypt secret JWT tokens. Using the Authorization Server's public
	// key to encrypt tokens, we ensure that those tokens can only be decrypted with the
	// private key, so only the Authorization Server can get the contents.
	encrypter, err := jose.NewEncrypter(
		jose.A128GCM,
		jose.Recipient{
			Algorithm: jose.RSA_OAEP,
			Key:       encoder.publicKeyJWKEnc(),
		},
		(&jose.EncrypterOptions{}).WithType("JWT").WithContentType("JWT"))
	if err != nil {
		return nil, err
	}

	encoder.encrypter = encrypter

	return encoder, nil
}

// Signed creates a new JWT token which is signed according to the JWS specification and
// contains the given claims.
// It uses the RS512 algorithm with the configured RSA key.
func (je *jwtEncoder) Signed(claims interface{}) (string, error) {
	raw, err := jwt.Signed(je.signer).Claims(claims).CompactSerialize()
	if err != nil {
		return "", err
	}

	return raw, nil
}

// Encrypted creates a new JWT token which is signed and encrypted according to the JWS and
// JWE specifications, containing the given claims.
// The algorithm used is RSA_OAEP with A128M encryption.
func (je *jwtEncoder) Encrypted(claims interface{}) (string, error) {
	raw, err := jwt.SignedAndEncrypted(je.signer, je.encrypter).Claims(claims).CompactSerialize()
	if err != nil {
		return "", err
	}

	return raw, nil
}

// ValidateSigned decodes the given JWT signed token. It validates the signature, checks that
// it has not expired and parses the claims into the given destination.
// Tokens are expected with the same algorithm than the Signed method.
func (je *jwtEncoder) ValidateSigned(token string, dest interface{}) error {
	decoded, err := jwt.ParseSigned(token)
	if err != nil {
		return err
	}

	if err := decoded.Claims(je.publicKeyJWKSig(), &dest); err != nil {
		return err
	}

	if claims, ok := dest.(jwt.Claims); ok {
		// Validate that token have not expired.
		return claims.Validate(jwt.Expected{Time: time.Now()})
	}

	return nil
}

// ValidateEncrypted decodes the given JWT signed and encrypted token. It validates the signature,
// checks that it has not expired and parses the claims into the given destination.
// Tokens are expected with the same algorithm than the Encrypted method.
func (je *jwtEncoder) ValidateEncrypted(token string, dest interface{}) error {
	encrypted, err := jwt.ParseSignedAndEncrypted(token)
	if err != nil {
		return err
	}

	decoded, err := encrypted.Decrypt(je.privateKeyJWKEnc())
	if err != nil {
		return err
	}

	if err := decoded.Claims(je.publicKeyJWKSig(), &dest); err != nil {
		return err
	}

	if claims, ok := dest.(jwt.Claims); ok {
		// Validate that token have not expired.
		return claims.Validate(jwt.Expected{Time: time.Now()})
	}

	return nil
}

func (je *jwtEncoder) privateKeyJWKSig() *jose.JSONWebKey {
	return &jose.JSONWebKey{
		Key:       je.PrivateKey,
		KeyID:     je.KeyID,
		Algorithm: string(jose.RS512),
		Use:       "sig",
	}
}

func (je *jwtEncoder) publicKeyJWKSig() *jose.JSONWebKey {
	return &jose.JSONWebKey{
		Key:       &je.PrivateKey.PublicKey,
		KeyID:     je.KeyID,
		Algorithm: string(jose.RS512),
		Use:       "sig",
	}
}

func (je *jwtEncoder) privateKeyJWKEnc() *jose.JSONWebKey {
	return &jose.JSONWebKey{
		Key:       je.PrivateKey,
		KeyID:     je.KeyID,
		Algorithm: string(jose.RSA_OAEP),
		Use:       "enc",
	}
}

func (je *jwtEncoder) publicKeyJWKEnc() *jose.JSONWebKey {
	return &jose.JSONWebKey{
		Key:       &je.PrivateKey.PublicKey,
		KeyID:     je.KeyID,
		Algorithm: string(jose.RSA_OAEP),
		Use:       "enc",
	}
}

// JWKS obtains the JWK Set definition of the public key used by the encoder to sign tokens,
// so other services can validate the token signature.
func (je *jwtEncoder) JWKS() *jose.JSONWebKeySet {
	return &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{*je.publicKeyJWKSig()},
	}
}
