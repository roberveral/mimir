package oauth

import (
	"testing"

	"github.com/roberveral/oauth-server/oauth/model"

	"github.com/stretchr/testify/assert"
)

func TestInvalidResponseTypeErrorReturnsCorrectReason(t *testing.T) {
	e := &InvalidResponseTypeError{model.CodeResponseType}

	assert.Equal(t,
		"Unsupported response_type: code",
		e.Error(),
		"Error message should be the expected")
}

func TestUserNotAuthenticatedErrorReturnsCorrectReason(t *testing.T) {
	e := &UserNotAuthenticatedError{}

	assert.Equal(t,
		"There isn't an authenticated user in context",
		e.Error(),
		"Error message should be the expected")
}

func TestInvalidGrantTypeErrorReturnsCorrectReason(t *testing.T) {
	e := &InvalidGrantTypeError{model.PasswordGrantType}

	assert.Equal(t,
		"Unsupported grant_type: password",
		e.Error(),
		"Error message should be the expected")
}

func TestClientNotFoundErrorReturnsCorrectReason(t *testing.T) {
	e := &ClientNotFoundError{"1234"}

	assert.Equal(t,
		"There isn't a client registered with client_id '1234'",
		e.Error(),
		"Error message should be the expected")
}

func TestInvalidRedirectURIErrorReturnsCorrectReason(t *testing.T) {
	e := &InvalidRedirectURIError{"https://example.org/cb", "1"}

	assert.Equal(t,
		"The given redirect_uri 'https://example.org/cb' is not registered for the client '1'",
		e.Error(),
		"Error message should be the expected")
}

func TestAuthorizationCodeConflictErrorReturnsCorrectReason(t *testing.T) {
	e := &AuthorizationCodeConflictError{}

	assert.Equal(t,
		"The provided authorization code is not valid for this client_id and/or redirect_uri",
		e.Error(),
		"Error message should be the expected")
}

func TestInvalidClientCredentialsErrorReturnsCorrectReason(t *testing.T) {
	e := &InvalidClientCredentialsError{}

	assert.Equal(t,
		"Invalid client credentials",
		e.Error(),
		"Error message should be the expected")
}

func TestUsedAuthorizationCodeErrorReturnsCorrectReason(t *testing.T) {
	e := &UsedAuthorizationCodeError{}

	assert.Equal(t,
		"The provided authorization code has already been used and it can only be used once",
		e.Error(),
		"Error message should be the expected")
}

func TestInvalidUserCredentialsErrorReturnsCorrectReason(t *testing.T) {
	e := &InvalidUserCredentialsError{}

	assert.Equal(t,
		"Invalid user credentials",
		e.Error(),
		"Error message should be the expected")
}
