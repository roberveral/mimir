package utils

import "context"

type contextKey string

var (
	// contextKeyUser is the key used to store the authenticated nickname in the request context.
	contextKeyUser = contextKey("authenticated-user")
)

// SetAuthenticatedUserInContext stores the userID of the user who performs a operation in the context.
func SetAuthenticatedUserInContext(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, contextKeyUser, userID)
}

// GetAuthenticatedUserFromContext retrieves the nickname of the user who performs the operation from the context.
func GetAuthenticatedUserFromContext(ctx context.Context) (string, bool) {
	nickname, ok := ctx.Value(contextKeyUser).(string)

	return nickname, ok
}
