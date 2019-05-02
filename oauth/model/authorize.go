package model

import "time"

// OAuthResponseType represents the different types of response types available
// during OAuth authorization phase.
type OAuthResponseType string

const (
	// CodeResponseType is the response type for the Authorization phase of the
	// Authorization Code flow.
	CodeResponseType = OAuthResponseType("code")
)

// OAuthAuthorizeInput is the model for OAuth Authorization requests. It contains all
// the parameters which may be required. Implementations must validate the parameters
// depending on the response type.
type OAuthAuthorizeInput struct {
	// Unique ID of the Client who requests authorization to act on behalf of the user.
	ClientID string

	// URI where the user must be redirected with the authorization code in order to
	// continue the OAuth flow. This must match the one stored when the client was
	// registered.
	RedirectURI string

	// Type of the expected response depending on the authorization flow
	// (only "code" is available).
	ResponseType OAuthResponseType

	// Optional state string which will be returned to the client in the callback.
	State string
}

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

// OAuthAuthorizationCode is the model for the Authorization Code token used in the
// Authorization Code Flow. Token providers are responsible for serializing/deserializing
// from/to this structure.
type OAuthAuthorizationCode struct {
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
