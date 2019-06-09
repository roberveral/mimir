package api

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/roberveral/mimir/oauth"
	"github.com/roberveral/mimir/oauth/model"
	"github.com/roberveral/mimir/utils"
)

// Client is the controller which contains the endpoint where OAuth
// clients are managed (registered, queried and deleted).
type Client struct {
	Controller
	manager *oauth.Manager
}

// NewClient creates a new Client controller, which uses the given
// OAuth Manager to manage registered clients.
func NewClient(manager *oauth.Manager) *Client {
	return &Client{
		Controller: NewController(clientErrorHandler),
		manager:    manager,
	}
}

// Register takes a router and configures the routes and handlers of the controller.
func (c *Client) Register(r *mux.Router) {
	r.Handle("/clients/{clientId}", c.Perform(c.DeleteClient)).Methods("DELETE")
	r.Handle("/clients/{clientId}", c.Perform(c.GetClient)).Methods("GET")
	r.Handle("/clients", c.Perform(c.RegisterClient)).Methods("POST")
	r.Handle("/clients", c.Perform(c.GetAllClients)).Methods("GET")
}

// RegisterClient if the endpoint which allows to register a new client in the
// Authorization Server. When the client is registered, random "client_id" and
// "client_secret" are generated for the client so it can perform the OAuth Authorization
// flows. The user who performs the client registration are set as owner, so it's
// the only one who can query the client and its associated secret.
func (c *Client) RegisterClient(rw http.ResponseWriter, r *http.Request) error {
	var input model.ClientInput
	if err := DecodeAndValidateJSON(r.Body, &input); err != nil {
		SendErrorResponse(http.StatusBadRequest, rw, err)
		return nil
	}

	client, err := c.manager.RegisterClient(r.Context(), &input)
	if err != nil {
		return err
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusCreated)
	return json.NewEncoder(rw).Encode(client)
}

// DeleteClient is the endpoint which allows to the client with the given client_id
// from the Authorization Server.
// Only the client owner can remove it.
func (c *Client) DeleteClient(rw http.ResponseWriter, r *http.Request) error {
	clientID := mux.Vars(r)["clientId"]

	if err := c.manager.DeleteClient(r.Context(), clientID); err != nil {
		return err
	}

	rw.WriteHeader(http.StatusOK)
	return nil
}

// GetClient is the endpoint which allows to obtain the information about the client
// registered with the given client_id. It returns the client_secret, so it can be
// queried after client registration. To ensure that the user has permission to see
// the client_secret, only the client owner is allowed to query the client information.
func (c *Client) GetClient(rw http.ResponseWriter, r *http.Request) error {
	clientID := mux.Vars(r)["clientId"]

	client, err := c.manager.GetClientByID(r.Context(), clientID)
	if err != nil {
		return err
	}

	user, _ := utils.GetAuthenticatedUserFromContext(r.Context())

	// Hide secret fields from a user which is not the owner
	if user != client.Owner {
		client.ClientSecret = ""
		client.GrantTypes = nil
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	return json.NewEncoder(rw).Encode(client)
}

// GetAllClients is the endpoint which allows to obtain all the clients registered
// in the Authorization Server which are visible to the user who performs the call,
// that is, the clients owned (created) by this user.
func (c *Client) GetAllClients(rw http.ResponseWriter, r *http.Request) error {
	user, _ := utils.GetAuthenticatedUserFromContext(r.Context())

	clients, err := c.manager.GetClientsByOwner(r.Context(), user)
	if err != nil {
		return err
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	return json.NewEncoder(rw).Encode(clients)
}

// Converts between possible errors during Client endpoints and status codes.
func clientErrorHandler(err error) int {
	switch err.(type) {
	case *oauth.ClientNotFoundError:
		return http.StatusNotFound
	case *oauth.UserNotAuthenticatedError:
		return http.StatusUnauthorized
	case *oauth.DeleteClientForbiddenError:
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}
