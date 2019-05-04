package oauth

import (
	"testing"

	"github.com/roberveral/oauth-server/oauth/model"
	"github.com/stretchr/testify/assert"
)

func TestGetAuthorizeHandler(t *testing.T) {
	manager := &Manager{}
	tests := []struct {
		name            string
		rt              model.OAuthResponseType
		expectedHandler authorizeHandler
		expectedError   error
	}{
		{
			"getAuthorizeHandler should return authCodeAuthorize for 'code' response_type",
			model.CodeResponseType,
			manager.authCodeAuthorize,
			nil,
		},
		{
			"getAuthorizeHandler should return InvalidResponseTypeError if invalid response_type",
			model.OAuthResponseType("other"),
			nil,
			&InvalidResponseTypeError{model.OAuthResponseType("other")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, err := manager.getAuthorizeHandler(tt.rt)
			if tt.expectedHandler == nil {
				assert.Nil(t, handler, "Handler must match")
			} else {
				assert.NotNil(t, handler, "Handler must match")
			}
			assert.Equal(t, tt.expectedError, err, "Error must match")
		})
	}
}
