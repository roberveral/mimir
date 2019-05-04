package jwt

import (
	"crypto/rsa"
	"time"

	"github.com/roberveral/oauth-server/oauth/model"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// TokenProvider implements AuthCodeProvider and AccessTokenProvider so the
// OAuth Authorization Server is managed in a stateless way using JWT tokens.
// Both tokens are signed with the RS512 algorithm and authorization codes are
// also encrypter with the configured public key so only the Authorization Server
// can read their contents.
type TokenProvider struct {
	encrypter  jose.Encrypter
	signer     jose.Signer
	privateKey *rsa.PrivateKey
	issuer     string
}

// New creates a TokenProvider configured to use the given key pair to sign and
// encrypt JWT tokens.
func New(privateKey *rsa.PrivateKey) (*TokenProvider, error) {
	// Signer used to sign JWT tokens. Using RS512 algorithm so the Authorization Server
	// signs each token with its private key and Resource Servers can validate the token
	// signature using the Authorization Server's public key.
	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.RS512,
			Key:       privateKey,
		},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return nil, err
	}

	// Encrypter used to encrypt secret JWT tokens. Using the Authorization Server's public
	// key to encrypt tokens, we ensure that those tokens can only be decrypter with the
	// private key, so only the Authorization Server can get the contents.
	encrypter, err := jose.NewEncrypter(
		jose.A128GCM,
		jose.Recipient{
			Algorithm: jose.RSA_OAEP,
			Key:       &privateKey.PublicKey,
		},
		(&jose.EncrypterOptions{}).WithType("JWT").WithContentType("JWT"))
	if err != nil {
		return nil, err
	}

	return &TokenProvider{
		encrypter:  encrypter,
		signer:     signer,
		privateKey: privateKey,
		issuer:     "oauth-server",
	}, nil
}

// GenerateCode issues a new code converting the OAuthAuthorizationCode info into a
// encrypted token which only the Authorization Server can decrypt.
func (j *TokenProvider) GenerateCode(authorizationCode *model.OAuthAuthorizationCode) (string, error) {
	claims := authorizationCodeClaims{
		&jwt.Claims{
			Subject:   authorizationCode.UserID,
			ID:        authorizationCode.TokenID,
			Expiry:    jwt.NewNumericDate(authorizationCode.ExpirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    j.issuer,
		},
		authorizationCode.ClientID,
		authorizationCode.RedirectURI,
	}
	rawToken, err := jwt.SignedAndEncrypted(j.signer, j.encrypter).Claims(claims).CompactSerialize()
	if err != nil {
		return "", err
	}

	return rawToken, nil
}

// ValidateCode decrypts the OAuthAuthorizationCode info from the given encrypted token.
// It must check signature along with expiration time.
func (j *TokenProvider) ValidateCode(code string) (*model.OAuthAuthorizationCode, error) {
	encrypted, err := jwt.ParseSignedAndEncrypted(code)
	if err != nil {
		return nil, err
	}

	token, err := encrypted.Decrypt(j.privateKey)
	if err != nil {
		return nil, err
	}

	claims := authorizationCodeClaims{}
	if err := token.Claims(&j.privateKey.PublicKey, &claims); err != nil {
		return nil, err
	}

	// Validate that tokens have not expired.
	err = claims.Validate(jwt.Expected{
		Time: time.Now(),
	})
	if err != nil {
		return nil, err
	}

	return &model.OAuthAuthorizationCode{
		TokenID:        claims.ID,
		UserID:         claims.Subject,
		ClientID:       claims.ClientID,
		RedirectURI:    claims.RedirectURI,
		ExpirationTime: claims.Expiry.Time(),
	}, nil
}

// GenerateToken issues a new token converting the OAuthAccessToken info into a signed token
// to ensure that the contents are not modified by a third party.
func (j *TokenProvider) GenerateToken(accessToken *model.OAuthAccessToken) (string, error) {
	claims := accessTokenClaims{
		&jwt.Claims{
			Subject:   accessToken.UserID,
			Expiry:    jwt.NewNumericDate(accessToken.ExpirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    j.issuer,
		},
		accessToken.ClientID,
		accessToken.Name,
		accessToken.Email,
		accessToken.PictureURI,
	}
	raw, err := jwt.Signed(j.signer).Claims(claims).CompactSerialize()
	if err != nil {
		return "", err
	}

	return raw, nil
}

// ValidateToken retrieves the OAuthAccessToken info from a signed token,
// which is validated to ensure that the contents have not been modified
// by a third party.
func (j *TokenProvider) ValidateToken(token string) (*model.OAuthAccessToken, error) {
	tok, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, err
	}

	claims := accessTokenClaims{}
	if err := tok.Claims(&j.privateKey.PublicKey, &claims); err != nil {
		return nil, err
	}

	// Validate that tokens have not expired.
	err = claims.Validate(jwt.Expected{
		Time: time.Now(),
	})
	if err != nil {
		return nil, err
	}

	return &model.OAuthAccessToken{
		ClientID:       claims.ClientID,
		ExpirationTime: claims.Expiry.Time(),
		User: &model.User{
			UserID:     claims.Subject,
			Name:       claims.Name,
			Email:      claims.Email,
			PictureURI: claims.PictureURI,
		},
	}, nil
}

// authorizationCodeClaims defines the struct of the JWT token used
// as Authorization Code.
type authorizationCodeClaims struct {
	*jwt.Claims
	ClientID    string `json:"cid,omitempty"`
	RedirectURI string `json:"redirect_uri,omitempty"`
}

// accessTokenClaims defines the struct of the JWT token used as
// Access Token.
type accessTokenClaims struct {
	*jwt.Claims
	ClientID   string `json:"cid,omitempty"`
	Name       string `json:"name,omitempty"`
	Email      string `json:"email,omitempty"`
	PictureURI string `json:"picture,omitempty"`
}
