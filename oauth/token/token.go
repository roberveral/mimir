package token

import "github.com/roberveral/oauth-server/oauth/model"

// AccessTokenProvider converts the OAuthAccessToken info into a signed token
// to ensure that the contents are not modified by a third party.
type AccessTokenProvider interface {
	// GenerateToken issues a new token converting the OAuthAccessToken info into a signed token
	// to ensure that the contents are not modified by a third party.
	GenerateToken(accessToken *model.OAuthAccessToken) (string, error)

	// ValidateToken retrieves the OAuthAccessToken info from a signed token,
	// which is validated to ensure that the contents have not been modified
	// by a third party.
	ValidateToken(token string) (*model.OAuthAccessToken, error)
}

// AuthorizationCodeProvider converts the OAuthAuthorizationCode info into a
// encrypted token which only the Authorization Server can decrypt.
type AuthorizationCodeProvider interface {
	// GenerateCode issues a new code converting the OAuthAuthorizationCode info into a
	// encrypted token which only the Authorization Server can decrypt.
	GenerateCode(authorizationCode *model.OAuthAuthorizationCode) (string, error)

	// ValidateCode decrypts the OAuthAuthorizationCode info from the given encrypted token.
	// It must check signature along with expiration time.
	ValidateCode(code string) (*model.OAuthAuthorizationCode, error)
}
