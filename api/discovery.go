package api

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/roberveral/mimir/oauth"
)

// Discovery is the controller used to expose the keys used by the Authorization Server to
// sign tokens.
type Discovery struct {
	Controller
	oauthManager *oauth.Manager
}

// NewDiscovery creates a new Discovery controller, which exposes and endpoint to retrieve
// the server JWK set.
func NewDiscovery(manager *oauth.Manager) *Discovery {
	return &Discovery{
		Controller:   NewController(nil),
		oauthManager: manager,
	}
}

// Register takes a router and configures the routes and handlers of the controller.
func (c *Discovery) Register(r *mux.Router) {
	r.Handle("/.well-known/jwks.json", c.Perform(c.GetJWKSet)).Methods("GET")
	r.Handle("/.well-known/openid-configuration", c.Perform(c.GetProviderConfiguration)).Methods("GET")
}

// GetProviderConfiguration obtains the OpenID Provider Metadata for this authorization
// server.
func (c *Discovery) GetProviderConfiguration(rw http.ResponseWriter, r *http.Request) error {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	return json.NewEncoder(rw).Encode(c.oauthManager.OpenIDProvider.Metadata)
}

// GetJWKSet is the endpoint which allows clients and Resource Servers to obtain the
// public key used by the Authorization Server to sign access tokens. This endpoint
// returns the keys following the JWK (JSON Web Key) Set standard.
func (c *Discovery) GetJWKSet(rw http.ResponseWriter, r *http.Request) error {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	return json.NewEncoder(rw).Encode(c.oauthManager.OpenIDProvider.JwtEncoder.JWKS())
}
