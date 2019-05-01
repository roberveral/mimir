package model

// User is the model for a Resource Owner fetched from the Identity Provider.
type User struct {
	// Unique ID of the user.
	UserID string

	// Full name of the user.
	Name string

	// Email of the user.
	Email string

	// URI to the profile picture of the user.
	PictureURI string
}
