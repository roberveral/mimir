package api

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/roberveral/oauth-server/oauth"
	"github.com/roberveral/oauth-server/oauth/model"
	"github.com/roberveral/oauth-server/utils"
)

// Authorize is the controller which contains the endpoint where OAuth
// Authorization is performed by a user.
type Authorize struct {
	Controller
	manager *oauth.Manager
}

// NewAuthorize creates a new Authorize controller, which uses the given OAuth Manager
// to perform the Authorize operation.
func NewAuthorize(manager *oauth.Manager) *Authorize {
	return &Authorize{
		Controller: NewController(authorizeErrorHandler),
		manager:    manager,
	}
}

// Register takes a router and configures the routes and handlers of the controller.
func (c *Authorize) Register(r *mux.Router) {
	r.Handle("/oauth/authorize", c.Perform(c.AuthorizeOAuthClient)).Methods("POST")
}

// AuthorizeOAuthClient is the OAuth Authorization action.
// This endpoint performs the first step in the OAuth 2 Authorization Code flow.
// When a call to this endpoint is performed by an authenticated user, it means
// that the user is authorizing the client defined by the client_id to act on his
// behalf and therefore to obtain an access token.
//
// The frontend MUST redirect the user to the returned redirect_uri in order to
// continue with the authorization flow.
func (c *Authorize) AuthorizeOAuthClient(rw http.ResponseWriter, r *http.Request) error {
	input := &model.OAuthAuthorizeInput{
		ResponseType:        model.OAuthResponseType(r.URL.Query().Get("response_type")),
		ClientID:            r.URL.Query().Get("client_id"),
		RedirectURI:         r.URL.Query().Get("redirect_uri"),
		State:               r.URL.Query().Get("state"),
		CodeChallenge:       r.URL.Query().Get("code_challenge"),
		CodeChallengeMethod: model.OAuthCodeChallengeMethod(r.URL.Query().Get("code_challenge_method")),
	}

	if err := utils.ValidateStruct(input); err != nil {
		SendErrorResponse(http.StatusBadRequest, rw, err)
		return nil
	}

	response, err := c.manager.Authorize(r.Context(), input)
	if err != nil {
		return err
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	return json.NewEncoder(rw).Encode(response)
}

// Converts between possible errors during Authorize and status codes.
func authorizeErrorHandler(err error) int {
	switch err.(type) {
	case *oauth.InvalidResponseTypeError:
		return http.StatusBadRequest
	case *oauth.ClientNotFoundError:
		return http.StatusBadRequest
	case *oauth.InvalidRedirectURIError:
		return http.StatusBadRequest
	case *oauth.UserNotAuthenticatedError:
		return http.StatusUnauthorized
	case *oauth.GrantTypeNotAllowedError:
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}
