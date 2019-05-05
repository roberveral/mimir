package api

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/roberveral/oauth-server/oauth"
	"github.com/roberveral/oauth-server/oauth/model"
	"github.com/roberveral/oauth-server/utils"
)

// Token is the controller which contains the endpoint where OAuth
// Token operation is performed to obtain a new token.
type Token struct {
	Controller
	manager *oauth.Manager
}

// NewToken creates a new Token controller, which uses the given error handler
// and the given OAuth Manager to perform the Token operation.
func NewToken(errorHandler ErrorHandler, manager *oauth.Manager) *Token {
	return &Token{
		Controller: Controller{errorHandler},
		manager:    manager,
	}
}

// Register takes a router and configures the routes and handlers of the controller.
func (c *Token) Register(r *mux.Router) {
	r.Handle("/oauth/token", c.Perform(c.GetOAuthToken)).Methods("POST")
}

// GetOAuthToken is the endpoint which allows a client to request an access token in
// order to access protected resources.
// Depending on the grant_type, this token can be to act on behalf of a given user or
// by the client itself.
//
// The access token is a JWT token signed with the public key of the authorization server
// and which contain the following information.
//  - sub (username or client_id, depending on the entity which holds the permission).
//  - cid (client who acts on behalf of the subject).
//  - name (name of the authenticated user).
//  - email (email of the authenticated user).
//  - picture (url to the user profile picture).
//
// Resource servers can verify the token integrity and expiration and get the requesting
// user from this token.
func (c *Token) GetOAuthToken(rw http.ResponseWriter, r *http.Request) error {
	r.ParseForm()

	input := &model.OAuthTokenInput{
		GrantType:    model.OAuthGrantType(r.FormValue("grant_type")),
		Code:         r.FormValue("code"),
		RedirectURI:  r.FormValue("redirect_uri"),
		ClientID:     r.FormValue("client_id"),
		ClientSecret: r.FormValue("client_secret"),
		Username:     r.FormValue("username"),
		Password:     r.FormValue("password"),
		Scope:        r.FormValue("scope"),
	}

	if err := utils.ValidateStruct(input); err != nil {
		SendErrorResponse(http.StatusBadRequest, rw, err)
		return nil
	}

	response, err := c.manager.Token(r.Context(), input)
	if err != nil {
		return err
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	return json.NewEncoder(rw).Encode(response)
}
