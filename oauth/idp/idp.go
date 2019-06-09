package idp

import (
	"context"
	"fmt"

	"github.com/roberveral/mimir/oauth/model"
)

// IdentityProvider is the service which manages user (Resource Owner) accounts and
// credentials.
type IdentityProvider interface {
	// GetUserByID obtains the information about a user from the IDP given the
	// userID. If the user doesn't exist (nil, nil) is returned.
	GetUserByID(ctx context.Context, userID string) (*model.User, error)

	// AuthenticateUser checks the credentials of a user and returns the user
	// information if the credentials are valid. Otherwise, a InvalidCredentialsError
	// should be returned.
	AuthenticateUser(ctx context.Context, username, password string) (*model.User, error)
}

// InvalidCredentialsError is the error returned by the IdentityProvider
// when the provided user credentials are invalid.
type InvalidCredentialsError struct{}

func (e *InvalidCredentialsError) Error() string {
	return fmt.Sprintf("Invalid username/password while authenticating with the Identity Provider")
}
