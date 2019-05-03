package oauth

import (
	"fmt"

	"github.com/roberveral/oauth-server/oauth/model"
)

// InvalidResponseTypeError is the error returned when an unsupported response_type
// is set in an OAuth Authorize request.
type InvalidResponseTypeError struct {
	rt model.OAuthResponseType
}

func (e *InvalidResponseTypeError) Error() string {
	return fmt.Sprintf("Unsupported response_type: %s", e.rt)
}

// UserNotAuthenticatedError is the error returned when an OAuth Authorize operation
// is performed without setting an authenticated User in context.
type UserNotAuthenticatedError struct{}

func (e *UserNotAuthenticatedError) Error() string {
	return "There isn't an authenticated user in context"
}

// InvalidGrantTypeError is the error returned when an unsupported grant_type
// is set in an OAuth Token request.
type InvalidGrantTypeError struct {
	gt model.OAuthGrantType
}

func (e *InvalidGrantTypeError) Error() string {
	return fmt.Sprintf("Unsupported grant_type: %s", e.gt)
}

// ClientNotFoundError is the error returned when a OAuth request is performed with
// a client_id not registered in the Authorization Server.
type ClientNotFoundError struct {
	clientID string
}

func (e *ClientNotFoundError) Error() string {
	return fmt.Sprintf("There isn't a client registered with client_id '%s'", e.clientID)
}

// InvalidRedirectURIError is the error returned when the redirect_uri used in an
// Authorization request doesn't match the one stored for the client.
type InvalidRedirectURIError struct {
	RedirectURI string
	ClientID    string
}

func (e *InvalidRedirectURIError) Error() string {
	return fmt.Sprintf("The given redirect_uri '%s' is not registered for the client '%s'", e.RedirectURI, e.ClientID)
}

// AuthorizationCodeConflictError is the error returned when the authorization code
// provided for getting a token was issued for a different client_id or redirect_url.
type AuthorizationCodeConflictError struct{}

func (e *AuthorizationCodeConflictError) Error() string {
	return "The provided authorization code is not valid for this client_id and/or redirect_uri"
}

// InvalidClientCredentialsError is the error returned when the provided client credentials
// (client_secret) doesn't match the registered for the client.
type InvalidClientCredentialsError struct{}

func (e *InvalidClientCredentialsError) Error() string {
	return "Invalid client credentials"
}

// UsedAuthorizationCodeError is the error returned when the authorization code
// has been stored as used, so it can't be used again.
type UsedAuthorizationCodeError struct{}

func (e *UsedAuthorizationCodeError) Error() string {
	return "The provided authorization code has already been used and it can only be used once"
}