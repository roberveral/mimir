package model

import "time"

// OAuthAuthorizeResponse is the response sent back by the Authorization Server
// when an OAuth authorization request is performed.
type OAuthAuthorizeResponse struct {
	// Authorization Code sent to the callback so it can be used to obtain an access
	// token. Contents are encrypted so only the Authorization Server can access the
	// token information.
	Code string `json:"code" validate:"required"`

	// URL of the client where the UI should redirect the user to complete the
	// authorization flow. This url contains all the required query params.
	RedirectURL string `json:"redirect_url" validate:"required"`
}

// AuthorizationCode is the model for the Authorization Code token used in the
// Authorization Code Flow. Token providers are responsible for serializing/deserializing
// from/to this structure.
type AuthorizationCode struct {
	// Unique UUID for the authorization code. This code should be checked against a repository
	// so authorization codes are only used once.
	TokenID string

	// ID of the user (Resource Owner) who authorizes the client to obtain
	// a token on his behalf.
	UserID string

	// ID of the Client who has requested authorization to act on behalf of
	// the user.
	ClientID string

	// URL that the Client has set as callback when requesting authorization.
	// This URL must match the one passed in when requesting an access token.
	RedirectURI string

	// Time when the authorization code expires and can't be used.
	ExpirationTime time.Time
}
