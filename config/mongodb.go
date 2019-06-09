package config

import "github.com/roberveral/mimir/oauth/repository/mongodb"

// MongoDB is the configuration related to the MongoDB connection.
type MongoDB struct {
	// URL is the full URL of the target MongoDB instance (including protocol).
	// Example: mongodb://localhost:27017
	URL string `required:"true"`
	// DB is the name of the database used for storing application's data.
	DB string `default:"oauth"`
	// Username used to authenticate with MongoDB.
	// Default value is ''
	Username string
	// Password used to authenticate with MongoDB.
	// Default value is ''
	Password string
}

// Store instantiates a new MongoDB store based on the configuration.
func (c *MongoDB) Store() (*mongodb.Store, error) {
	return mongodb.New(c.URL, c.DB)
}
