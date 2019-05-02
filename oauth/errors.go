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
