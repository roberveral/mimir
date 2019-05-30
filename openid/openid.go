package openid

import (
	"github.com/roberveral/oauth-server/jwt"
	"github.com/roberveral/oauth-server/oauth/idp"
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
	Address AddressClaim `json:"address,omitempty"`
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

type Manager struct {
	jwtEncoder jwt.Encoder
	issuer     string
	idp        idp.IdentityProvider
}
