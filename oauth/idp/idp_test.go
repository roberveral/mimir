package idp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInvalidCredentialsErrorReturnsCorrectReason(t *testing.T) {
	ice := &InvalidCredentialsError{}

	assert.Equal(t,
		"Invalid username/password while authenticating with the Identity Provider",
		ice.Error(),
		"Error message should be the expected")
}
