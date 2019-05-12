package config

import "github.com/roberveral/oauth-server/oauth/idp/ldap"

// LDAP is the configuration related to the LDAP connection as user directory.
type LDAP struct {
	// URL is the full URL of the LDAP server (including protocol).
	// Example: ldaps://localhost
	URL string `required:"true"`
	// UserDN is the user used to bind and query to the LDAP server.
	UserDN string `required:"true" split_words:"true"`
	// Password is the password of the user used to bind and query the LDAP server.
	Password string `required:"true"`
	// BaseDN is the base tree used to search for users in the LDAP directory.
	// Example: dc=example,dc=org
	// Default value is ''
	BaseDN string `split_words:"true"`
	// UserQuery is the template for the query performed to find a user in the
	// LDAP directory. It must contain the pattern '%s', which is replaced by
	// the queried user ID.
	// Default value is: '(&(objectClass=inetOrgPerson)(uid=%s))'
	UserQuery string `default:"(&(objectClass=inetOrgPerson)(uid=%s))" split_words:"true"`
	// NameAttr is the attribute of an user entry in LDAP which contains the full
	// name of the user.
	// Default value is: name
	NameAttr string `default:"name" split_words:"true"`
	// MailAttr is the attribute of an user entry in LDAP which contains the mail
	// address of the user.
	// Default value is: mail
	MailAttr string `default:"mail" split_words:"true"`
}

// IdentityProvider instantiates a new LDAP identity provider based on the configuration.
func (c *LDAP) IdentityProvider() (*ldap.IdentityProvider, error) {
	return ldap.New(c.URL, c.UserDN, c.Password,
		ldap.WithBaseDN(c.BaseDN),
		ldap.WithUserQuery(c.UserQuery),
		ldap.WithNameAttr(c.NameAttr),
		ldap.WithMailAttr(c.MailAttr))
}
