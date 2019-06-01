package api

import (
	"encoding/json"
	"net/http"

	"github.com/roberveral/oauth-server/utils"

	"github.com/gorilla/mux"
	"github.com/roberveral/oauth-server/oauth"
)

// OpenID is the controller which contains the OpenID specific endpoints.
type OpenID struct {
	Controller
	oauthManager *oauth.Manager
}

// NewOpenID creates a new OpenID controller, which exposes an endpoint to check the user
// identity given an access token with the proper scopes.
func NewOpenID(manager *oauth.Manager) *OpenID {
	return &OpenID{
		Controller:   NewController(openidErrorHandler),
		oauthManager: manager,
	}
}

// Register takes a router and configures the routes and handlers of the controller.
func (c *OpenID) Register(r *mux.Router) {
	r.Handle("/openid/userinfo", c.Perform(c.GetUserInfo)).Methods("GET", "POST")
}

// GetUserInfo allows to obtain the information about the authenticated user with
// an access token.
func (c *OpenID) GetUserInfo(rw http.ResponseWriter, r *http.Request) error {
	token, err := utils.ExtractBearerToken(r)
	if err != nil {
		return err
	}

	accessToken, err := c.oauthManager.ValidateAccessToken(token)
	if err != nil {
		return err
	}

	info, err := c.oauthManager.OpenIDProvider.UserInfo(r.Context(), accessToken)
	if err != nil {
		return err
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	return json.NewEncoder(rw).Encode(info)
}

// Converts between possible errors and status codes.
func openidErrorHandler(err error) int {
	switch err.(type) {
	default:
		return http.StatusUnauthorized
	}
}
