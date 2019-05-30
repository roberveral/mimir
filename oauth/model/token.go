package model

import "time"

// OAuthGrantType is the different grant flows available for obtaining an
// OAuth 2 token.
type OAuthGrantType string

const (
	// AuthorizationCodeGrantType represents the Authorization Code flow.
	AuthorizationCodeGrantType = OAuthGrantType("authorization_code")

	// PasswordGrantType represents the Password flow.
	PasswordGrantType = OAuthGrantType("password")

	// ClientCredentialsGrantType represents the Client Credentials flow.
	ClientCredentialsGrantType = OAuthGrantType("client_credentials")
)

// OAuthTokenType is the different token types that the server can return
// when obtaining an OAuth token.
type OAuthTokenType string

const (
	// BearerTokenType is the most common token type.
	BearerTokenType = OAuthTokenType("bearer")
)

// OAuthTokenInput is the model for OAuth token requests. It contains all the parameters
// which may be required by any flow. Is responsability of each flow to validate that the
// required parameters are present.
type OAuthTokenInput struct {
	// The grant type for the Authentication Flow required.
	GrantType OAuthGrantType `json:"grant_type" validate:"required"`

	// Authorization Code received by the Authorize phase.
	// (Authorization Code Flow - REQUIRED)
	Code string `json:"code,omitempty"`

	// Must be identical to the redirect URI used in the Authorization phase.
	// (Authorization Code Flow - REQUIRED)
	RedirectURI string `json:"redirect_uri,omitempty"`

	// Unique identifier of the client that requests the access token.
	ClientID string `json:"client_id" validate:"required"`

	// The client’s secret. This ensures that the request to get the access token
	// is made only from the client.
	// (Authorization Code Flow - OPTIONAL, Client Credentials Flow - REQUIRED)
	ClientSecret string `json:"client_secret,omitempty"`

	// The user’s username that they entered in the client application.
	// (Password Flow - REQUIRED)
	Username string `json:"username,omitempty"`

	// The user’s password that they entered in the client application.
	// (Password Flow - REQUIRED)
	Password string `json:"password,omitempty"`

	// One or more scope values indicating which parts of the user's account
	// the client wish to access. (Password and Client Credentials Flows - OPTIONAL)
	Scope []string `json:"scope,omitempty"`

	// The code verifier for the PKCE request, that the app originally generated before
	// the authorization request. (Authorization Code Flow - OPTIONAL)
	CodeVerifier string `json:"code_verifier,omitempty"`
}

// OAuthTokenResponse is the response sent back by the Authorization Server
// when an OAuth token request is performed.
type OAuthTokenResponse struct {
	// Access token for the client and user, which can be used to access
	// Resource Servers. It's a JWT token, which can be decoded with the
	// Authorization Server public key.
	AccessToken string `json:"access_token" validate:"required"`

	// The type of token this is, typically just the string “bearer”.
	TokenType OAuthTokenType `json:"token_type" validate:"required"`

	// Time in seconds until token expiration.
	ExpiresIn float32 `json:"expires_in" validate:"required"`
}

// OAuthAccessToken is the model for the Access Token generated by the Authorization Server
// to grant access to Resource Servers to a concrete client, who may act on behalf of
// a user (resource owner).
type OAuthAccessToken struct {
	// Unique ID of the client which has access.
	ClientID string

	// Unique ID of the user which has authorized the application. Empty if the application
	// acts by itself (Client Credentials grant type)
	UserID string

	// Optional space separated string indicating the access scopes requested by the client.
	Scope []string

	// Time when the token is no longer valid.
	ExpirationTime time.Time
}
