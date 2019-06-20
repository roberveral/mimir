package openid

import (
	"context"
	"time"

	"github.com/roberveral/mimir/jwt"
	"github.com/roberveral/mimir/oauth/idp"
	"github.com/roberveral/mimir/oauth/model"
	"github.com/roberveral/mimir/utils"
)

// IDToken is a security token that contains Claims about the Authentication of an End-User
// by an Authorization Server when using a Client, and potentially other requested Claims.
type IDToken struct {
	Claims
	// Issuer Identifier for the Issuer of the response. The iss value is a case sensitive URL using the
	// https scheme that contains scheme, host, and optionally, port number and path components and no query
	// or fragment components.
	Issuer string `json:"iss"`
	// Audience(s) that this ID Token is intended for. It MUST contain the OAuth 2.0 client_id of the
	// Relying Party as an audience value.
	Audience string `json:"aud"`
	// Expiration time on or after which the ID Token MUST NOT be accepted for processing.
	ExpirationTime int64 `json:"exp"`
	// Time at which the JWT was issued.
	IssuedAt int64 `json:"iat"`
	// Time when the End-User authentication occurred.
	AuthTime int64 `json:"auth_time,omitempty"`
	// String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
	// The value is passed through unmodified from the Authentication Request to the ID Token.
	Nonce string `json:"nonce,omitempty"`
}

// Claims about the End-User and the Authentication event.
type Claims struct {
	// Identifier for the End-User at the Issuer.
	Subject string `json:"sub"`
	// End-User's full name in displayable form including all name parts.
	Name string `json:"name,omitempty"`
	// Given name(s) or first name(s) of the End-User.
	GivenName string `json:"given_name,omitempty"`
	// Surname(s) or last name(s) of the End-User.
	FamilyName string `json:"family_name,omitempty"`
	// Middle name(s) of the End-User.
	MiddleName string `json:"middle_name,omitempty"`
	// Casual name of the End-User that may or may not be the same as the given_name.
	Nickname string `json:"nickname,omitempty"`
	// Shorthand name by which the End-User wishes to be referred to at the RP, such as janedoe or j.doe.
	PreferredUsername string `json:"preferred_username,omitempty"`
	// URL of the End-User's profile page.
	Profile string `json:"profile,omitempty"`
	// URL of the End-User's profile picture.
	Picture string `json:"picture,omitempty"`
	// URL of the End-User's Web page or blog.
	Website string `json:"website,omitempty"`
	// End-User's preferred e-mail address.
	Email string `json:"email,omitempty"`
	// True if the End-User's e-mail address has been verified; otherwise false.
	EmailVerified bool `json:"email_verified,omitempty"`
	// End-User's gender. Values defined by this specification are female and male.
	// Other values MAY be used when neither of the defined values are applicable.
	Gender string `json:"gender,omitempty"`
	// End-User's birthday, represented as an ISO 8601:2004 [ISO8601‑2004] YYYY-MM-DD format.
	// The year MAY be 0000, indicating that it is omitted
	Birthdate string `json:"birthdate,omitempty"`
	// String from zoneinfo time zone database representing the End-User's time zone.
	// For example, Europe/Paris or America/Los_Angeles.
	Zoneinfo string `json:"zoneinfo,omitempty"`
	// End-User's locale, represented as a BCP47 [RFC5646] language tag.
	// For example, en-US or fr-CA.
	Locale string `json:"locale,omitempty"`
	// End-User's preferred telephone number.
	PhoneNumber string `json:"phone_number,omitempty"`
	// True if the End-User's phone number has been verified; otherwise false.
	PhoneNumberVerified bool `json:"phone_number_verified,omitempty"`
	// End-User's preferred postal address.
	Address *AddressClaim `json:"address,omitempty"`
	// Time the End-User's information was last updated.
	// Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
	UpdatedAt int64 `json:"updated_at,omitempty"`
}

// AddressClaim represents a physical mailing address.
type AddressClaim struct {
	// Full mailing address, formatted for display or use on a mailing label.
	Formatted string `json:"formatted,omitempty"`
	// Full street address component, which MAY include house number, street name,
	// Post Office Box, and multi-line extended street address information.
	StreetAddress string `json:"street_address,omitempty"`
	// City or locality component.
	Locality string `json:"locality,omitempty"`
	// State, province, prefecture, or region component.
	Region string `json:"region,omitempty"`
	// Zip code or postal code component.
	PostalCode string `json:"postal_code,omitempty"`
	// Country name component.
	Country string `json:"country,omitempty"`
}

// ProviderMetadata describes the configuration of OpenID Providers.
type ProviderMetadata struct {
	// URL using the https scheme with no query or fragment component that the OP asserts as its Issuer Identifier.
	Issuer string `json:"issuer"`
	// URL of the OP's OAuth 2.0 Authorization Endpoint.
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	// URL of the OP's OAuth 2.0 Token Endpoint.
	TokenEndpoint string `json:"token_endpoint,omitempty"`
	// URL of the OP's UserInfo Endpoint.
	UserInfoEndpoint string `json:"userinfo_endpoint,omitempty"`
	// URL of the OP's JSON Web Key Set document.
	JwksURI string `json:"jwks_uri"`
	// URL of the OP's Dynamic Client Registration Endpoint.
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"`
	// JSON array containing a list of the OAuth 2.0 [RFC6749] scope values that this server supports.
	ScopesSupported []string `json:"scopes_supported,omitempty"`
	// JSON array containing a list of the OAuth 2.0 response_type values that this OP supports.
	ResponseTypesSupported []string `json:"response_types_supported"`
	// JSON array containing a list of the OAuth 2.0 Grant Type values that this OP supports.
	GrantTypesSupported []string `json:"grant_types_supported,omitempty"`
	// JSON array containing a list of the Subject Identifier types that this OP supports. Valid types include pairwise and public.
	SubjectTypesSupported []string `json:"subject_types_supported,omitempty"`
	// JSON array containing a list of the JWS signing algorithms (alg values) supported by the
	// OP for the ID Token to encode the Claims in a JWT.
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported,omitempty"`
	// JSON array containing a list of Client Authentication methods supported by this Token Endpoint.
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	// JSON array containing the list of code_challenge_method supported by the authorization endpoint
	// for PKCE extension.
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`
}

// Declaration of the different scopes supported by the OpenID Connect spec
const (
	OpenIDScope  = "openid"
	EmailScope   = "email"
	ProfileScope = "profile"
	AddressScope = "address"
	PhoneScope   = "phone"
)

// Declaration of the different token authentication methods.
const (
	ClientSecretPostTokenAuthMethod  = "client_secret_post"
	ClientSecretBasicTokenAuthMethod = "client_secret_basic"
	ClientSecretJWTTokenAuthMethod   = "client_secret_jwt"
	PrivateKeyJWTTokenAuthMethod     = "private_key_jwt"
)

// Provider allows to obtain authentication information about a user according
// to the OpenID Connect specification.
type Provider struct {
	Metadata   *ProviderMetadata
	JwtEncoder jwt.Encoder
	idp        idp.IdentityProvider
}

// NewProvider creates a new Provider which uses the given encoder for serializing
// ID Tokens, sets the given issuer and fetches user data from the given IDP.
func NewProvider(metadata *ProviderMetadata, jwtEncoder jwt.Encoder, idp idp.IdentityProvider) *Provider {
	return &Provider{
		JwtEncoder: jwtEncoder,
		Metadata:   metadata,
		idp:        idp,
	}
}

// UserInfo obtains the claims with the information about the user who granted permissions
// with the given OAuth access token.
// The returned claims depends on the specified scopes (what info the user allowed to share),
// according to the OpenID Connect specification.
func (m *Provider) UserInfo(ctx context.Context, accessToken *model.OAuthAccessToken) (*Claims, error) {
	scopeSet := model.NewScopeSet(accessToken.Scope)

	// Check that the scope 'openid' is granted, and therefore is a valid OpenID Connect
	// request
	if !scopeSet.Contains(OpenIDScope) {
		return nil, &ScopeNotAllowedError{}
	}

	// Get authenticated user information, so the client can act on his behalf
	user, err := m.idp.GetUserByID(ctx, accessToken.UserID)
	if err != nil {
		return nil, err
	}

	claims := &Claims{}

	// Always set the subject as the user ID
	claims.Subject = user.UserID

	if scopeSet.Contains(EmailScope) {
		// Scope 'email': email, email_verified
		claims.Email = user.Email
	}

	if scopeSet.Contains(ProfileScope) {
		// Scope 'profile': name, family_name, given_name, middle_name, nickname,
		// preferred_username, profile, picture, website, gender, birthdate, zoneinfo,
		// locale, updated_at
		claims.Name = user.Name
		claims.Picture = user.PictureURI
	}

	if scopeSet.Contains(AddressScope) {
		// Scope 'address': address
	}

	if scopeSet.Contains(PhoneScope) {
		// Scope 'phone': phone_number, phone_number_verified
	}

	return claims, nil
}

// IdentityToken obtains an ID Token with the information about the user who granted permissions
// with the given OAuth access token.
// The returned claims depends on the specified scopes (what info the user allowed to share),
// according to the OpenID Connect specification.
func (m *Provider) IdentityToken(ctx context.Context, accessToken *model.OAuthAccessToken) (*IDToken, error) {
	claims, err := m.UserInfo(ctx, accessToken)
	if err != nil {
		return nil, err
	}

	authTime, _ := utils.GetUserAuthTimeFromContext(ctx)

	return &IDToken{
		Claims:         *claims,
		Issuer:         m.Metadata.Issuer,
		Audience:       accessToken.ClientID,
		ExpirationTime: accessToken.ExpirationTime.Unix(),
		IssuedAt:       time.Now().Unix(),
		Nonce:          accessToken.Nonce,
		AuthTime:       authTime.Unix(),
	}, nil
}

// IdentityTokenSerialize obtains an ID Token with the information about the user who granted permissions
// with the given OAuth access token, serialized as a signed JWT.
// The returned claims depends on the specified scopes (what info the user allowed to share),
// according to the OpenID Connect specification.
func (m *Provider) IdentityTokenSerialize(ctx context.Context, accessToken *model.OAuthAccessToken) (string, error) {
	token, err := m.IdentityToken(ctx, accessToken)
	if err != nil {
		return "", err
	}

	return m.JwtEncoder.Signed(token)
}

// ScopeNotAllowedError is the error returned when trying to obtain the OpenID user
// information without allowing the scope 'openid'.
type ScopeNotAllowedError struct{}

func (e *ScopeNotAllowedError) Error() string {
	return "Scope 'openid' is not granted to the given access_token"
}
