package utils

import (
	"context"
	"time"
)

type contextKey string

var (
	// contextKeyUser is the key used to store the authenticated nickname in the request context.
	contextKeyUser     = contextKey("authenticated-user")
	contextKeyAuthTime = contextKey("authenticated-user-auth-time")
)

// SetAuthenticatedUserInContext stores the userID of the user who performs a operation in the context.
func SetAuthenticatedUserInContext(ctx context.Context, userID string, authTime time.Time) context.Context {
	return context.WithValue(context.WithValue(ctx, contextKeyUser, userID), contextKeyAuthTime, authTime)
}

// GetAuthenticatedUserFromContext retrieves the nickname of the user who performs the operation from the context.
func GetAuthenticatedUserFromContext(ctx context.Context) (string, bool) {
	nickname, ok := ctx.Value(contextKeyUser).(string)

	return nickname, ok
}

// GetUserAuthTimeFromContext retrieves the time the user who performs the operation was authenticated from the context.
func GetUserAuthTimeFromContext(ctx context.Context) (time.Time, bool) {
	authTime, ok := ctx.Value(contextKeyUser).(time.Time)

	return authTime, ok
}
