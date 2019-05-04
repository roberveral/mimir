package utils

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetAuthenticatedUserInContext(t *testing.T) {
	tests := []struct {
		name   string
		ctx    context.Context
		userID string
	}{
		{
			"SetAuthenticatedUserInContext must insert user in context values",
			context.Background(),
			"a user",
		},
		{
			"SetAuthenticatedUserInContext must overwrite user in context values",
			context.WithValue(context.Background(), contextKeyUser, "other user"),
			"a user",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SetAuthenticatedUserInContext(tt.ctx, tt.userID)
			assert.Equal(t, tt.userID, result.Value(contextKeyUser), tt.name)
		})
	}
}

func TestGetAuthenticatedUserFromContext(t *testing.T) {
	tests := []struct {
		name         string
		ctx          context.Context
		expectedUser string
		expectedOk   bool
	}{
		{
			"GetAuthenticatedUserFromContext should return the user and true when present",
			context.WithValue(context.Background(), contextKeyUser, "a user"),
			"a user",
			true,
		},
		{
			"GetAuthenticatedUserFromContext should return empty and false when not present",
			context.Background(),
			"",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, ok := GetAuthenticatedUserFromContext(tt.ctx)
			assert.Equal(t, tt.expectedUser, user, fmt.Sprintf("%s - Users don't match", tt.name))
			assert.Equal(t, tt.expectedOk, ok, fmt.Sprintf("%s - User presence doesn't match", tt.name))
		})
	}
}
