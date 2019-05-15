package model

// Client is the model for application clients registered in the Authorization Server.
// Clients are able to obtain access tokens to act on behalf of a user or themselves against
// the Resource servers.
type Client struct {
	// Unique identifier of the client, used for exchanging OAuth tokens.
	ClientID string `json:"client_id" validate:"required"`

	// Randomly generated secret associated to the client, used for exchanging OAuth tokens.
	ClientSecret string `json:"client_secret,omitempty" validate:"required"`

	// Name of the client (for instance the application name).
	Name string `json:"name" validate:"required"`

	// URL to the main page of the client application.
	URL string `json:"url" validate:"required,url"`

	// URL to the callback used in the Authorization Code flow.
	RedirectURI string `json:"redirect_uri" validate:"required,url"`

	// URL to the Application image logo.
	Logo string `json:"logo,omitempty" validate:"omitempty,url"`

	// The OAuth grant types that the client is allowed to use in order to obtain
	// an access token.
	GrantTypes []OAuthGrantType `json:"grant_types,omitempty" validate:"required,gte=1,dive,oneof=authorization_code password client_credentials"`

	// User who registered the client.
	Owner string `json:"owner" validate:"required"`
}

// ClientInput is the model used for registering new clients in the Authorization Server.
type ClientInput struct {
	// Name of the client (for instance the application name).
	Name string `json:"name" validate:"required"`

	// URL to the main page of the client application.
	URL string `json:"url" validate:"required,url"`

	// URL to the callback used in the Authorization Code flow.
	RedirectURI string `json:"redirect_uri" validate:"required,url"`

	// URL to the Application image logo.
	Logo string `json:"logo,omitempty" validate:"omitempty,url"`

	// The OAuth grant types that the client is allowed to use in order to obtain
	// an access token.
	GrantTypes []OAuthGrantType `json:"grant_types" validate:"required,gte=1,dive,oneof=authorization_code password client_credentials"`
}
