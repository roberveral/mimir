package model

// Client is the model for application clients registered in the Authorization Server.
// Clients are able to obtain access tokens to act on behalf of a user or themselves against
// the Resource servers.
type Client struct {
	// Unique identifier of the client, used for exchanging OAuth tokens.
	ClientID string `json:"client_id" validate:"required"`

	// Randomly generated secret associated to the client, used for exchanging OAuth tokens.
	ClientSecret string `json:"client_secret" validate:"required"`

	// Name of the client (for instance the application name).
	Name string `json:"name" validate:"required"`

	// URL to the main page of the client application.
	URL string `json:"url" validate:"required"`

	// URL to the callback used in the Authorization Code flow.
	RedirectURL string `json:"redirect_url" validate:"required"`

	// User who registered the client.
	Owner string `json:"owner" validate:"required"`
}

// ClientInput is the model used for registering new clients in the Authorization Server.
type ClientInput struct {
	// Name of the client (for instance the application name).
	Name string `json:"name" validate:"required"`

	// URL to the main page of the client application.
	URL string `json:"url" validate:"required"`

	// URL to the callback used in the Authorization Code flow.
	RedirectURL string `json:"redirect_url" validate:"required"`
}
