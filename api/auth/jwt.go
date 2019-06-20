package auth

import (
	"net/http"
	"strings"
	"time"

	"github.com/roberveral/mimir/api"
	"github.com/roberveral/mimir/oauth/model"
	"github.com/roberveral/mimir/utils"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// Jwt allows to generate and validate JWT tokens for the Authorization Server itself,
// so this token identifies the user (Resource Owner) agains the Authorization Server
// only.
type Jwt struct {
	expirationTime time.Duration
	signatureKey   string
	issuer         string
	signer         jose.Signer
}

// NewJwt creates a new TokenService which uses JWT tokens. When a new token is issued, it lasts
// for the given expirationTime, it has set the given issuer and is signed using the HS512
// algorithm with the given signatureKey.
func NewJwt(expirationTime time.Duration, signatureKey string, issuer string) (*Jwt, error) {
	// Signer used to sign JWT tokens. Using HS512 algorithm so the Authorization Server
	// signs each token with a private secret that it only has, so no other server can
	// verify the token integrity and therefore only the Authorization Server trusts the
	// token contents.
	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.HS512,
			Key:       []byte(signatureKey),
		},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return nil, err
	}

	return &Jwt{expirationTime, signatureKey, issuer, signer}, nil
}

// GenerateToken issues a JWT token for the given User so it can be authenticated
// against the Authorization Server.
func (j *Jwt) GenerateToken(user *model.User) (string, error) {
	claims := tokenClaims{
		&jwt.Claims{
			Subject:   user.UserID,
			Expiry:    jwt.NewNumericDate(time.Now().Add(j.expirationTime)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    j.issuer,
		},
		user.Name,
		user.Email,
		user.PictureURI,
	}
	raw, err := jwt.Signed(j.signer).Claims(claims).CompactSerialize()
	if err != nil {
		return "", err
	}

	return raw, nil
}

// DecodeToken validates and extracts the User info from a JWT token, so
// the user is properly authenticated.
func (j *Jwt) DecodeToken(rawToken string) (*model.User, error) {
	token, err := jwt.ParseSigned(rawToken)
	if err != nil {
		return nil, err
	}

	claims := tokenClaims{}
	if err := token.Claims([]byte(j.signatureKey), &claims); err != nil {
		return nil, err
	}

	// Validate that tokens have not expired.
	err = claims.Validate(jwt.Expected{
		Time: time.Now(),
	})
	if err != nil {
		return nil, err
	}

	return &model.User{
		UserID:     claims.Subject,
		Name:       claims.Name,
		Email:      claims.Email,
		PictureURI: claims.PictureURI,
		AuthTime:   claims.IssuedAt.Time(),
	}, nil
}

// Handler returns an http.Handler which extracts the authentication token from
// each request (header 'Authorization: Bearer <token>') and stores the userID
// in the request context, if authenticated. If there isn't a valid token, an
// error is returned in the HTTP response.
func (j *Jwt) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		token, err := fromBearerToken(r)
		if err != nil {
			api.SendErrorResponse(http.StatusUnauthorized, rw, err)
			return
		}

		user, err := j.DecodeToken(token)
		if err != nil {
			api.SendErrorResponse(http.StatusUnauthorized, rw, err)
			return
		}

		newRequest := r.WithContext(utils.SetAuthenticatedUserInContext(r.Context(), user.UserID, user.AuthTime))

		h.ServeHTTP(rw, newRequest)
	})
}

// fromBearerToken obtains the authentication token from a request using the "Bearer"
// authorization scheme. 'Authorization: Bearer {token}'
func fromBearerToken(r *http.Request) (string, error) {
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

// tokenClaims defines the struct of the JWT token used as
// Access Token.
type tokenClaims struct {
	*jwt.Claims
	Name       string `json:"name,omitempty"`
	Email      string `json:"email,omitempty"`
	PictureURI string `json:"picture,omitempty"`
}

// MissingAuthenticationToken is the error returned when an authentication token is not properly
// present in the HTTP request.
type MissingAuthenticationToken struct{}

func (e *MissingAuthenticationToken) Error() string {
	return "Missing authentication token. Authorization header format must be 'Bearer {token}'"
}
