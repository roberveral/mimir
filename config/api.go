package config

import (
	"time"

	"github.com/roberveral/oauth-server/api/auth"
	"github.com/roberveral/oauth-server/utils"
	"github.com/rs/cors"

	log "github.com/sirupsen/logrus"
)

// Api contains all the configuration related to the REST API endpoints
// exposed by the Authorization Server.
type Api struct {
	// Port where the API server is listening.
	// Default value is 8000
	Port int `default:"8000"`
	// JWT is the configuration related to the authentication tokens in the
	// REST API.
	JWT ApiJWT
	// CORS is the configuration related to the CORS configuration of the
	// exposed API.
	CORS ApiCORS
}

// ApiJWT is the configuration related to the authentication tokens in the
// REST API.
type ApiJWT struct {
	// TTL is the time of expiration of new tokens, as a duration string.
	// Example: 10s, 3h
	// Default value is 3h
	TTL TTL `default:"3h"`
	// Key is the key used to sign the authentication token.
	Key string `required:"true"`
	// Issuer is the issuer set in the authentication tokens.
	// Default value is 'oauth-server-api'
	Issuer string `default:"oauth-server-api"`
}

// ApiCORS is the configuration related to the CORS configuration of the
// exposed API.
type ApiCORS struct {
	// AllowedOrigins is a list of origins a cross-domain request can be executed from.
	// If the special "*" value is present in the list, all origins will be allowed.
	// An origin may contain a wildcard (*) to replace 0 or more characters
	// (i.e.: http://*.domain.com). Usage of wildcards implies a small performance penalty.
	// Only one wildcard can be used per origin.
	// Default value is ["*"]
	AllowedOrigins []string `default:"*" split_words:"true"`
	// AllowedHeaders is list of non simple headers the client is allowed to use with
	// cross-domain requests.
	// If the special "*" value is present in the list, all headers will be allowed.
	// Default value is ["*"] but "Origin" is always appended to the list.
	AllowedHeaders []string `default:"*" split_words:"true"`
	// ExposedHeaders indicates which headers are safe to expose to the API of a CORS
	// API specification
	// Default value is []
	ExposedHeaders []string `split_words:"true"`
}

// Cors instantiates a new Cors middleware based on the configuration.
func (c *Api) Cors(debug bool) *cors.Cors {
	log.Infof("API CORS configuration: %+v", c.CORS)
	return cors.New(cors.Options{
		AllowedOrigins: c.CORS.AllowedOrigins,
		AllowedHeaders: c.CORS.AllowedHeaders,
		ExposedHeaders: c.CORS.ExposedHeaders,
		Debug:          debug,
	})
}

// Authentication instantiates a new JWT authentication based on the configuration.
func (c *Api) Authentication() (*auth.Jwt, error) {
	key := c.JWT.Key
	if key == "" {
		log.Warn("No signing key provided for JWT Authentication. Using a random string")
		key = utils.RandString(20)
	}
	return auth.NewJwt(time.Duration(c.JWT.TTL),
		key,
		c.JWT.Issuer)
}
