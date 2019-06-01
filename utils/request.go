package utils

import (
	"net/http"
	"strings"
)

// ExtractBearerToken obtains the authentication token from a request using the "Bearer"
// authorization scheme. 'Authorization: Bearer {token}'
func ExtractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", &MissingAuthenticationToken{}
	}

	authHeaderFields := strings.Fields(authHeader)
	if len(authHeaderFields) != 2 || strings.ToLower(authHeaderFields[0]) != "bearer" {
		return "", &MissingAuthenticationToken{}
	}

	return authHeaderFields[1], nil
}

// MissingAuthenticationToken is the error returned when an authentication token is not properly
// present in the HTTP request.
type MissingAuthenticationToken struct{}

func (e *MissingAuthenticationToken) Error() string {
	return "Missing authentication token. Authorization header format must be 'Bearer {token}'"
}
