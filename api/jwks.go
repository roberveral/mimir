package api

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"gopkg.in/square/go-jose.v2"
)

// Jwks is the controller used to expose the keys used by the Authorization Server to
// sign tokens.
type Jwks struct {
	Controller
	jwks *jose.JSONWebKeySet
}

// NewJwks creates a new Jwks controller, which exposes and endpoint to retrieve
// the server JWK set.
func NewJwks(jwks *jose.JSONWebKeySet) *Jwks {
	return &Jwks{
		Controller: NewController(nil),
		jwks:       jwks,
	}
}

// Register takes a router and configures the routes and handlers of the controller.
func (c *Jwks) Register(r *mux.Router) {
	r.Handle("/oauth/jwks", c.Perform(c.GetJWKSet)).Methods("GET")
}

// GetJWKSet is the endpoint which allows clients and Resource Servers to obtain the
// public key used by the Authorization Server to sign access tokens. This endpoint
// returns the keys following the JWK (JSON Web Key) Set standard.
func (c *Jwks) GetJWKSet(rw http.ResponseWriter, r *http.Request) error {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	return json.NewEncoder(rw).Encode(c.jwks)
}
