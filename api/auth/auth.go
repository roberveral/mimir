package auth

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/roberveral/mimir/api"
	"github.com/roberveral/mimir/oauth/idp"
)

// Authentication is the controller which contains the endpoints
// to perform user (Resource Owner) authentication against the
// Authorization Server. Authentication is delegated to the Identity
// Provider.
type Authentication struct {
	api.Controller
	jwt              *Jwt
	identityProvider idp.IdentityProvider
}

// NewAuthentication creates a new Authentication controller for user authentication.
func NewAuthentication(jwt *Jwt, identityProvider idp.IdentityProvider) *Authentication {
	return &Authentication{
		Controller:       api.NewController(errorHandler),
		jwt:              jwt,
		identityProvider: identityProvider,
	}
}

// Register takes a router and configures the routes and handlers of the controller.
func (a *Authentication) Register(r *mux.Router) {
	r.Handle("/auth/sign-in", a.Perform(a.SignIn)).Methods("POST")
}

// SignIn is the endpoint which allows to authenticate a User against the server IDP
// (Identity Provider) and obtains an authentication token to serve as session to
// interact with the rest of the endpoints of the Authorization Server, including
// the OAuth Authorize endpoint.
func (a *Authentication) SignIn(rw http.ResponseWriter, r *http.Request) error {
	var input UserLoginInput
	if err := api.DecodeAndValidateJSON(r.Body, &input); err != nil {
		api.SendErrorResponse(http.StatusBadRequest, rw, err)
		return nil
	}

	user, err := a.identityProvider.AuthenticateUser(r.Context(), input.Username, input.Password)
	if err != nil {
		return err
	}

	token, err := a.jwt.GenerateToken(user)
	if err != nil {
		return err
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	return json.NewEncoder(rw).Encode(&AuthenticationToken{token})
}

// Converts possible errors during authentication to the proper status code.
func errorHandler(err error) int {
	switch err.(type) {
	case *idp.InvalidCredentialsError:
		return http.StatusUnauthorized
	default:
		return http.StatusInternalServerError
	}
}

// UserLoginInput models the credentials of the user to authenticate.
type UserLoginInput struct {
	// Username of the user to authenticate.
	Username string `json:"username" validate:"required"`

	// Password of the user to authenticate.
	Password string `json:"password" validate:"required"`
}

// AuthenticationToken returns the token for a successfully authenticated
// user.
type AuthenticationToken struct {
	// Authentication token
	Token string `json:"token" validate:"required"`
}
