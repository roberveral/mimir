package token

import "github.com/roberveral/oauth-server/oauth/model"

// AccessTokenProvider converts the AccessToken info into a signed token
// to ensure that the contents are not modified by a third party.
type AccessTokenProvider interface {
	// GenerateToken issues a new token converting the AccessToken info into a signed token
	// to ensure that the contents are not modified by a third party.
	GenerateToken(accessToken *model.AccessToken) (string, error)

	// ValidateToken retrieves the AccessToken info from a signed token,
	// which is validated to ensure that the contents have not been modified
	// by a third party.
	ValidateToken(token string) (*model.AccessToken, error)
}

// AuthorizationCodeProvider converts the AuthorizationCode info into a
// encrypted token which only the Authorization Server can decrypt.
type AuthorizationCodeProvider interface {
	// GenerateCode issues a new code converting the AuthorizationCode info into a
	// encrypted token which only the Authorization Server can decrypt.
	GenerateCode(authorizationCode *model.AuthorizationCode) (string, error)

	// ValidateCode descrypts the AuthorizationCode info from the given encrypted token.
	ValidateCode(code string) (*model.AuthorizationCode, error)
}
