package ldap

import (
	"context"
	"fmt"

	"github.com/roberveral/mimir/oauth/idp"
	"github.com/roberveral/mimir/oauth/model"
	log "github.com/sirupsen/logrus"
	"gopkg.in/ldap.v3"
)

// IdentityProvider is an IdentityProvider which retrives user from a
// LDAP directory.
type IdentityProvider struct {
	url       string
	baseDN    string
	userQuery string
	nameAttr  string
	mailAttr  string
	conn      *ldap.Conn
}

// Option is a functional option used to configure the IdentityProvider and
// set value to optional parameters that have a default.
type Option func(l *IdentityProvider)

// WithBaseDN sets the given baseDN as the base tree for LDAP searches in the
// IdentityProvider, so user entries can be found.
func WithBaseDN(baseDN string) Option {
	return func(l *IdentityProvider) {
		l.baseDN = baseDN
	}
}

// WithUserQuery sets the query used to find user entries given the user ID.
// The place where the userID should be is indicated by the format string '%s'.
// Example: "(&(objectClass=inetOrgPerson)(uid=%s))" => "(&(objectClass=inetOrgPerson)(uid=jdoe))"
func WithUserQuery(userQuery string) Option {
	return func(l *IdentityProvider) {
		l.userQuery = userQuery
	}
}

// WithNameAttr sets the LDAP attribute from where the user's full name is obtained in
// a user entry.
func WithNameAttr(nameAttr string) Option {
	return func(l *IdentityProvider) {
		l.nameAttr = nameAttr
	}
}

// WithMailAttr sets the LDAP attribute from where the user's mail address is obtained in
// a user entry.
func WithMailAttr(mailAttr string) Option {
	return func(l *IdentityProvider) {
		l.mailAttr = mailAttr
	}
}

// New creates a new Identity Provider connected to the given LDAP server
// (must contain protocol ldap:// or ldaps://) using the given credentials
// to read the directory (given user must have read permissions)
func New(url, userDN, password string, options ...Option) (*IdentityProvider, error) {
	log.Info("Connecting to LDAP server: ", url)
	conn, err := ldap.DialURL(url)
	if err != nil {
		log.Error("Unable to connect to LDAP: ", err.Error())
		return nil, err
	}

	log.Info("Binding to LDAP as user: ", userDN)
	if err := conn.Bind(userDN, password); err != nil {
		log.Error("Unable to bind to LDAP: ", err.Error())
		return nil, err
	}

	identityProvider := &IdentityProvider{
		url:       url,
		baseDN:    "",
		userQuery: "(&(objectClass=inetOrgPerson)(uid=%s))",
		nameAttr:  "name",
		mailAttr:  "mail",
		conn:      conn,
	}

	for _, opt := range options {
		opt(identityProvider)
	}

	log.Info("LDAP connection established")

	return identityProvider, nil
}

// GetUserByID obtains the information about a user from the IDP given the
// userID. If the user doesn't exist (nil, nil) is returned.
func (l *IdentityProvider) GetUserByID(ctx context.Context, userID string) (*model.User, error) {
	searchRequest := ldap.NewSearchRequest(
		l.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(l.userQuery, userID),
		[]string{l.nameAttr, l.mailAttr},
		nil,
	)

	log.Debugf("Performing LDAP query with base: %s; filter: %s; attributes: %s",
		searchRequest.BaseDN, searchRequest.Filter, searchRequest.Attributes)

	sr, err := l.conn.Search(searchRequest)
	if err != nil {
		log.Error("LDAP query failed: ", err.Error())
		return nil, err
	}

	if len(sr.Entries) != 1 {
		log.Errorf("UserID '%s' not found in LDAP", userID)
		return nil, nil
	}

	userEntry := sr.Entries[0]
	return &model.User{
		UserID: userID,
		Name:   userEntry.GetAttributeValue(l.nameAttr),
		Email:  userEntry.GetAttributeValue(l.mailAttr),
	}, nil
}

// AuthenticateUser checks the credentials of a user and returns the user
// information if the credentials are valid. Otherwise, a InvalidCredentialsError
// should be returned.
func (l *IdentityProvider) AuthenticateUser(ctx context.Context, username string, password string) (*model.User, error) {
	searchRequest := ldap.NewSearchRequest(
		l.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(l.userQuery, username),
		[]string{"dn", l.nameAttr, l.mailAttr},
		nil,
	)

	log.Debugf("Performing LDAP query with base: %s; filter: %s; attributes: %s",
		searchRequest.BaseDN, searchRequest.Filter, searchRequest.Attributes)

	sr, err := l.conn.Search(searchRequest)
	if err != nil {
		log.Error("LDAP query failed: ", err.Error())
		return nil, err
	}

	if len(sr.Entries) != 1 {
		log.Errorf("UserID '%s' not found in LDAP", username)
		return nil, &idp.InvalidCredentialsError{}
	}

	userEntry := sr.Entries[0]
	user := &model.User{
		UserID: username,
		Name:   userEntry.GetAttributeValue(l.nameAttr),
		Email:  userEntry.GetAttributeValue(l.mailAttr),
	}

	log.Debugf("Performing LDAP bind for DN '%s' to check credentials", userEntry.DN)

	// Bind as the user to verify their password
	conn, err := ldap.DialURL(l.url)
	if err != nil {
		log.Error("Unable to connect to LDAP: ", err.Error())
		return nil, err
	}
	defer conn.Close()
	err = conn.Bind(userEntry.DN, password)
	if err != nil {
		log.Error("Unable to bind to LDAP: ", err.Error())
		return nil, &idp.InvalidCredentialsError{}
	}

	log.Debugf("User '%s' successfully authenticated", username)

	return user, nil
}
