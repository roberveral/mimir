package config

import (
	"time"

	"github.com/kelseyhightower/envconfig"
	log "github.com/sirupsen/logrus"
)

// App contains all the configuration for the Authoriation Server.
type App struct {
	// Debug indicates if the app should log enhanced traces of the execution.
	Debug bool
	// API is the configuration related to the Authorization Server REST
	// endpoints.
	API Api
	// Ldap is the configuration related to the LDAP connection as user
	// directory.
	Ldap LDAP
	// Mongo is the configuration related to the MongoDB connection as
	// persistence.
	Mongo MongoDB
	// OAuth is the configuration related to the OAuth core logic of the
	// Authorization Server.
	OAuth OAuth
}

// TTL is an alias for time.Duration to add decode capabilities from
// environment variable.
type TTL time.Duration

// Decode takes the value of an environment variable and parses it into a time.Duration.
func (t *TTL) Decode(value string) error {
	ttl, err := time.ParseDuration(value)
	*t = TTL(ttl)
	return err
}

// Load reads the application configuration from environment variables.
func Load() (*App, error) {
	log.Info("Loading configuration from environment variables")
	var conf App
	err := envconfig.Process("app", &conf)
	if err != nil {
		return nil, err
	}

	log.Info("Configuration loaded")
	return &conf, err
}
