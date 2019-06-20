package token

import (
	"time"

	"github.com/roberveral/mimir/jwt"
	"github.com/roberveral/mimir/oauth/model"

	jose "gopkg.in/square/go-jose.v2/jwt"
)

// Encoder is an interface with contains all the methods required to encode and decode
// OAuth tokens: access token and authorization code.
type Encoder interface {
	// EncodeAccessToken issues a new token converting the OAuthAccessToken info into a signed token
	// to ensure that the contents are not modified by a third party.
	EncodeAccessToken(accessToken *model.OAuthAccessToken) (string, error)

	// DecodeAccessToken retrieves the OAuthAccessToken info from a signed token,
	// which is validated to ensure that the contents have not been modified
	// by a third party.
	DecodeAccessToken(token string) (*model.OAuthAccessToken, error)

	// EncodeAuthorizationCode issues a new code converting the OAuthAuthorizationCode info into a
	// encrypted token which only the Authorization Server can decrypt.
	EncodeAuthorizationCode(authorizationCode *model.OAuthAuthorizationCode) (string, error)

	// DecodeAuthorizationCode decrypts the OAuthAuthorizationCode info from the given encrypted token.
	// It must check signature along with expiration time.
	DecodeAuthorizationCode(code string) (*model.OAuthAuthorizationCode, error)
}

type jwtTokenEncoder struct {
	jwtEncoder jwt.Encoder
	issuer     string
}

// NewJwt creates a new Encoder which uses JWT as the way to encode the OAuth tokens.
// It uses the given JwtEncoder to sign and encrypt tokens as needed.
func NewJwt(jwtEncoder jwt.Encoder, issuer string) Encoder {
	return &jwtTokenEncoder{
		jwtEncoder: jwtEncoder,
		issuer:     issuer,
	}
}

// EncodeAccessToken issues a new token converting the OAuthAccessToken info into a signed token
// to ensure that the contents are not modified by a third party.
func (j *jwtTokenEncoder) EncodeAccessToken(accessToken *model.OAuthAccessToken) (string, error) {
	claims := accessTokenClaims{
		&jose.Claims{
			Subject:   accessToken.UserID,
			Expiry:    jose.NewNumericDate(accessToken.ExpirationTime),
			IssuedAt:  jose.NewNumericDate(time.Now()),
			NotBefore: jose.NewNumericDate(time.Now()),
			Issuer:    j.issuer,
		},
		accessToken.ClientID,
		accessToken.Scope,
	}

	return j.jwtEncoder.Signed(&claims)
}

// DecodeAccessToken retrieves the OAuthAccessToken info from a signed token,
// which is validated to ensure that the contents have not been modified
// by a third party.
func (j *jwtTokenEncoder) DecodeAccessToken(token string) (*model.OAuthAccessToken, error) {
	claims := accessTokenClaims{}
	if err := j.jwtEncoder.ValidateSigned(token, &claims); err != nil {
		return nil, err
	}

	return &model.OAuthAccessToken{
		ClientID:       claims.ClientID,
		UserID:         claims.Subject,
		Scope:          claims.Scope,
		ExpirationTime: claims.Expiry.Time(),
	}, nil
}

// EncodeAuthorizationCode issues a new code converting the OAuthAuthorizationCode info into a
// encrypted token which only the Authorization Server can decrypt.
func (j *jwtTokenEncoder) EncodeAuthorizationCode(authorizationCode *model.OAuthAuthorizationCode) (string, error) {
	claims := authorizationCodeClaims{
		&jose.Claims{
			Subject:   authorizationCode.UserID,
			ID:        authorizationCode.TokenID,
			Expiry:    jose.NewNumericDate(authorizationCode.ExpirationTime),
			IssuedAt:  jose.NewNumericDate(time.Now()),
			NotBefore: jose.NewNumericDate(time.Now()),
			Issuer:    j.issuer,
		},
		authorizationCode.ClientID,
		authorizationCode.RedirectURI,
		authorizationCode.Scope,
		authorizationCode.CodeChallenge,
		authorizationCode.Nonce,
	}

	return j.jwtEncoder.Encrypted(&claims)
}

// DecodeAuthorizationCode decrypts the OAuthAuthorizationCode info from the given encrypted token.
// It must check signature along with expiration time.
func (j *jwtTokenEncoder) DecodeAuthorizationCode(code string) (*model.OAuthAuthorizationCode, error) {
	claims := authorizationCodeClaims{}
	if err := j.jwtEncoder.ValidateEncrypted(code, &claims); err != nil {
		return nil, err
	}

	return &model.OAuthAuthorizationCode{
		TokenID:        claims.ID,
		UserID:         claims.Subject,
		ClientID:       claims.ClientID,
		RedirectURI:    claims.RedirectURI,
		Scope:          claims.Scope,
		ExpirationTime: claims.Expiry.Time(),
		CodeChallenge:  claims.CodeChallenge,
		Nonce:          claims.Nonce,
	}, nil
}

// authorizationCodeClaims defines the struct of the JWT token used
// as Authorization Code.
type authorizationCodeClaims struct {
	*jose.Claims
	ClientID      string   `json:"aud,omitempty"`
	RedirectURI   string   `json:"redirect_uri,omitempty"`
	Scope         []string `json:"scope,omitempty"`
	CodeChallenge string   `json:"code_challenge,omitempty"`
	Nonce         string   `json:"nonce,omitempty"`
}

// accessTokenClaims defines the struct of the JWT token used as
// Access Token.
type accessTokenClaims struct {
	*jose.Claims
	ClientID string   `json:"aud,omitempty"`
	Scope    []string `json:"scope,omitempty"`
}
