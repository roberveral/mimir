package oauth

import (
	"context"
	"net/url"
	"time"

	"github.com/roberveral/mimir/openid"
	"github.com/roberveral/mimir/utils"

	"github.com/roberveral/mimir/jwt"
	"github.com/roberveral/mimir/oauth/idp"
	"github.com/roberveral/mimir/oauth/model"
	"github.com/roberveral/mimir/oauth/repository"
	"github.com/roberveral/mimir/oauth/repository/mongodb"
	"github.com/roberveral/mimir/oauth/token"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

const (
	tokenExpirationTime = 10800
	codeExpirationTime  = 10
)

// authorizeHandler is the function signature that the handlers for the different
// response types in the OAuth Authorization phase must implement.
type authorizeHandler func(context.Context, *model.Client, *model.OAuthAuthorizeInput) (*model.OAuthAuthorizationCode, error)

// authorizeHandler is the function signature that the handlers for the different
// grant types in the OAuth Token exchange phase must implement.
type tokenHandler func(context.Context, *model.Client, *model.OAuthTokenInput) (*model.OAuthAccessToken, error)

// Manager contains all the OAuth 2 core logic. It allows to manage clients,
// to authorize a client and to obtain access tokens.
type Manager struct {
	clientRepository   repository.ClientRepository
	identityProvider   idp.IdentityProvider
	authCodeRepository repository.AuthorizationCodeRepository
	tokenEncoder       token.Encoder
	OpenIDProvider     *openid.Provider
}

// NewManager creates a new OAuth Manager which uses MongoDB as persistence and JWT as token
// provider.
func NewManager(identityProvider idp.IdentityProvider, store *mongodb.Store, jwtEncoder jwt.Encoder, openidMetadata *openid.ProviderMetadata) *Manager {
	return &Manager{
		clientRepository:   store,
		identityProvider:   identityProvider,
		authCodeRepository: store,
		tokenEncoder:       token.NewJwt(jwtEncoder, openidMetadata.Issuer),
		OpenIDProvider:     openid.NewProvider(openidMetadata, jwtEncoder, identityProvider),
	}
}

// getAuthorizeHandler obtains the handler for the given response_type in the OAuth
// Authorization phase. If the response_type is not supported a InvalidResponseTypeError
// is returned.
func (m *Manager) getAuthorizeHandler(rt model.OAuthResponseType) (authorizeHandler, error) {
	// Supported response types are added to this map
	authorizeHandlers := map[model.OAuthResponseType]authorizeHandler{
		model.CodeResponseType: m.authCodeAuthorize,
	}

	handler, ok := authorizeHandlers[rt]
	if !ok {
		return nil, &InvalidResponseTypeError{rt}
	}

	return handler, nil
}

// getTokenHandler obtains the handler for the given grant_type in the OAuth
// Token Exchange phase. If the grant_type is not supported a InvalidGrantTypeError is
// returned.
func (m *Manager) getTokenHandler(gt model.OAuthGrantType) (tokenHandler, error) {
	// Supported grant types are added to this map
	tokenHandlers := map[model.OAuthGrantType]tokenHandler{
		model.AuthorizationCodeGrantType: m.authCodeToken,
		model.PasswordGrantType:          m.passwordToken,
		model.ClientCredentialsGrantType: m.clientToken,
	}

	handler, ok := tokenHandlers[gt]
	if !ok {
		return nil, &InvalidGrantTypeError{gt}
	}

	return handler, nil
}

// GetClientByID obtains the client registered in the Authorization Server with the given
// client_id. If not present, a ClientNotFoundError is returned.
func (m *Manager) GetClientByID(ctx context.Context, clientID string) (*model.Client, error) {
	client, err := m.clientRepository.GetClientByID(ctx, clientID)
	if err != nil {
		return nil, err
	} else if client == nil {
		return nil, &ClientNotFoundError{clientID}
	}

	return client, nil
}

// GetClientsByOwner obtains all the clients registered in the Authorization Server by
// a given owner.
func (m *Manager) GetClientsByOwner(ctx context.Context, owner string) ([]*model.Client, error) {
	return m.clientRepository.GetAllClientsByOwner(ctx, owner)
}

// RegisterClient registers a new client with the Authorization Server. A registered client can
// perform OAuth Authorization to get access to protected resources. On registration, a client_id
// and client_secret are generated and returned.
func (m *Manager) RegisterClient(ctx context.Context, input *model.ClientInput) (*model.Client, error) {
	// Retrieve authenticated user who registers the client from context
	user, ok := utils.GetAuthenticatedUserFromContext(ctx)
	if !ok {
		return nil, &UserNotAuthenticatedError{}
	}

	client := &model.Client{
		ClientID:     uuid.New().String(),
		ClientSecret: utils.RandString(20),
		Name:         input.Name,
		URL:          input.URL,
		RedirectURI:  input.RedirectURI,
		Owner:        user,
		Logo:         input.Logo,
		GrantTypes:   input.GrantTypes,
	}

	return m.clientRepository.StoreClient(ctx, client)
}

// DeleteClient removes a registered client from the Authorization Server. If the client
// doesn't exist a ClientNotFoundError is returned.
func (m *Manager) DeleteClient(ctx context.Context, clientID string) error {
	client, err := m.GetClientByID(ctx, clientID)
	if err != nil {
		return err
	}

	user, ok := utils.GetAuthenticatedUserFromContext(ctx)
	if !ok {
		return &UserNotAuthenticatedError{}
	}

	// AUTHORIZATION: only owner can delete a client
	if user != client.Owner {
		return &DeleteClientForbiddenError{}
	}

	return m.clientRepository.DeleteClient(ctx, client)
}

// Authorize performs the OAuth authorization request where a user (Resource Owner) grants
// authorization to a client to retrieve a token to act on his behalf. This step returns an
// authorization code which is sent to the client and can be used to obtain an access token.
func (m *Manager) Authorize(ctx context.Context, input *model.OAuthAuthorizeInput) (*model.OAuthAuthorizeResponse, error) {
	log.Infof("Processing authorize request of type and client: %s - %s", input.ResponseType, input.ClientID)
	// Check that the authorized client exists
	client, err := m.GetClientByID(ctx, input.ClientID)
	if err != nil {
		return nil, err
	}

	// Check allowed grant types for clients: authorize call required Authorization Code grant type.
	if !containsGrantType(client.GrantTypes, model.AuthorizationCodeGrantType) {
		return nil, &GrantTypeNotAllowedError{client.ClientID, model.AuthorizationCodeGrantType}
	}

	// If missing RedirectURI, use the provided during client registration
	if input.RedirectURI == "" {
		log.Warn("No redirect_uri parameter set. Using client registered redirect_uri")
		input.RedirectURI = client.RedirectURI
	} else if input.RedirectURI != client.RedirectURI {
		return nil, &InvalidRedirectURIError{input.RedirectURI, client.ClientID}
	}

	// Execute the logic for generating the authorization code depending on the response_type.
	handler, err := m.getAuthorizeHandler(input.ResponseType)
	if err != nil {
		return nil, err
	}

	authCode, err := handler(ctx, client, input)
	if err != nil {
		return nil, err
	}

	// Encode the token using the defined provider. The authorization code must be encoded
	// in a way that only the Authorization Server can modify or decode the contents.
	code, err := m.tokenEncoder.EncodeAuthorizationCode(authCode)
	if err != nil {
		return nil, err
	}

	// Prepare the callback URI with the proper query parameters
	redirectURL, err := url.Parse(input.RedirectURI)
	if err != nil {
		return nil, err
	}

	q := redirectURL.Query()
	q.Set("code", code)
	if input.State != "" {
		q.Set("state", input.State)
	}
	redirectURL.RawQuery = q.Encode()

	log.Infof("Authorization granted to client: %s", input.ClientID)

	response := &model.OAuthAuthorizeResponse{
		Code:        code,
		RedirectURI: redirectURL.String(),
	}

	return response, nil
}

// Token performs the OAuth token request where a client request an access token to act on behalf of a
// user (Resource Owner who has authorized the application) or itself (depending on the grant_type). This
// step returns an access token which can be used to access resources in the Resource Servers.
func (m *Manager) Token(ctx context.Context, input *model.OAuthTokenInput) (*model.OAuthTokenResponse, error) {
	log.Infof("Processing token request of type and client: %s - %s", input.GrantType, input.ClientID)
	// Check that the client who requests a token exists.
	client, err := m.GetClientByID(ctx, input.ClientID)
	if err != nil {
		return nil, err
	}

	// Check allowed grant types for clients
	if !containsGrantType(client.GrantTypes, input.GrantType) {
		return nil, &GrantTypeNotAllowedError{client.ClientID, input.GrantType}
	}

	// Execute the logic for validating the request and generating a token depending on the grant_type.
	handler, err := m.getTokenHandler(input.GrantType)
	if err != nil {
		return nil, err
	}

	accessToken, err := handler(ctx, client, input)
	if err != nil {
		return nil, err
	}

	// Encode the token using the defined provider. Access tokens must be encoded in a way that
	// they can't be modified but every one should be able to decode and validate the contents.
	// (Should be signed by the Authorization Server)
	encodedToken, err := m.tokenEncoder.EncodeAccessToken(accessToken)
	if err != nil {
		return nil, err
	}

	log.Infof("Token generated for client: %s", input.ClientID)

	response := &model.OAuthTokenResponse{
		AccessToken: encodedToken,
		TokenType:   model.BearerTokenType,
		ExpiresIn:   tokenExpirationTime,
	}

	// OPENID CONNECT: if scope 'openid' and user defined, include and IDToken in the response
	if model.NewScopeSet(accessToken.Scope).Contains(openid.OpenIDScope) && accessToken.UserID != "" {
		log.Debugf("OpenID Connect request with scopes: %v. Generating ID Token", accessToken.Scope)
		idToken, err := m.OpenIDProvider.IdentityTokenSerialize(ctx, accessToken)
		if err != nil {
			return nil, err
		}
		response.IDToken = idToken
	}

	return response, nil
}

// authCodeAuthorize is the handler for the 'authorize' of the Authorization Code flow.
// It generates an authorization code for the authorized client, including all the info required
// to validate the request to obtain an access token.
func (m *Manager) authCodeAuthorize(ctx context.Context, client *model.Client, input *model.OAuthAuthorizeInput) (*model.OAuthAuthorizationCode, error) {
	log.Debug("Using Authorization Code flow")
	// Retrieve authenticated user (Resource Owner) who authorizes the client to act on
	// his behalf.
	user, ok := utils.GetAuthenticatedUserFromContext(ctx)
	if !ok {
		return nil, &UserNotAuthenticatedError{}
	}

	var codeChallenge string
	// PKCE Extension: if code_challenge is set, get the SHA-256 and store it
	if input.CodeChallenge != "" {
		log.Debug("Using PKCE Extension during Authorization")
		if input.CodeChallengeMethod == model.S256CodeChallengeMethod {
			codeChallenge = input.CodeChallenge
		} else {
			codeChallenge = utils.GenerateSHA256NoPadding(input.CodeChallenge)
		}
	}

	code := &model.OAuthAuthorizationCode{
		TokenID:        uuid.New().String(),
		UserID:         user,
		ClientID:       client.ClientID,
		RedirectURI:    input.RedirectURI,
		Scope:          input.Scope,
		ExpirationTime: time.Now().Add(codeExpirationTime * time.Second),
		CodeChallenge:  codeChallenge,
	}

	return code, nil
}

func (m *Manager) authCodeToken(ctx context.Context, client *model.Client, input *model.OAuthTokenInput) (*model.OAuthAccessToken, error) {
	log.Debug("Using Authorization Code grant")
	// Decode and validate authorization code to check if it was issued by the Authorization Server and
	// it has not expired.
	code, err := m.tokenEncoder.DecodeAuthorizationCode(input.Code)
	if err != nil {
		return nil, err
	}

	// Check that the authorization code was issued for the same client_id and redirect_uri
	if code.ClientID != client.ClientID || code.RedirectURI != input.RedirectURI {
		return nil, &AuthorizationCodeConflictError{}
	}

	if input.ClientSecret == "" && input.CodeVerifier == "" {
		return nil, &CredentialsRequiredError{}
	}

	// Check client credentials, to ensure that the request comes from the client
	if input.ClientSecret != "" && input.ClientSecret != client.ClientSecret {
		return nil, &InvalidClientCredentialsError{}
	}

	// If no secret provider, check PKCE extension code challenge
	if input.ClientSecret == "" &&
		code.CodeChallenge != utils.GenerateSHA256NoPadding(input.CodeVerifier) {
		return nil, &InvalidCodeVerifierError{}
	}

	// Check if the authorization code has been already used
	alreadyUsed, err := m.authCodeRepository.CheckAuthorizationCodeByID(ctx, code.TokenID)
	if err != nil {
		return nil, err
	}

	if alreadyUsed {
		return nil, &UsedAuthorizationCodeError{}
	}

	accessToken := &model.OAuthAccessToken{
		ClientID:       client.ClientID,
		UserID:         code.UserID,
		Scope:          code.Scope,
		ExpirationTime: time.Now().Add(tokenExpirationTime * time.Second),
	}

	// Mark the authorization code as used, so it's rejected for now on.
	if err = m.authCodeRepository.StoreUsedAuthorizationCode(ctx, code); err != nil {
		return nil, err
	}

	return accessToken, nil
}

func (m *Manager) passwordToken(ctx context.Context, client *model.Client, input *model.OAuthTokenInput) (*model.OAuthAccessToken, error) {
	log.Debug("Using Password grant")
	// Check client credentials if secret set, not mandatory.
	if input.ClientSecret != "" && input.ClientSecret != client.ClientSecret {
		return nil, &InvalidClientCredentialsError{}
	}

	// Check that the user credentials are valid in the IDP
	user, err := m.identityProvider.AuthenticateUser(ctx, input.Username, input.Password)
	if err != nil {
		return nil, &InvalidUserCredentialsError{}
	}

	// Issue access token for the user
	accessToken := &model.OAuthAccessToken{
		ClientID:       client.ClientID,
		UserID:         user.UserID,
		Scope:          input.Scope,
		ExpirationTime: time.Now().Add(tokenExpirationTime * time.Second),
	}

	return accessToken, nil
}

func (m *Manager) clientToken(ctx context.Context, client *model.Client, input *model.OAuthTokenInput) (*model.OAuthAccessToken, error) {
	log.Debug("Using Client Credentials grant")
	// Check client credentials, to ensure that the request comes from the client
	if input.ClientSecret != client.ClientSecret {
		return nil, &InvalidClientCredentialsError{}
	}

	// Issue access token for the client to act on its own behalf
	accessToken := &model.OAuthAccessToken{
		ClientID:       client.ClientID,
		Scope:          input.Scope,
		ExpirationTime: time.Now().Add(tokenExpirationTime * time.Second),
	}

	return accessToken, nil
}

// ValidateAccessToken decodes and ensures that the given access token is valid (has not expired).
func (m *Manager) ValidateAccessToken(token string) (*model.OAuthAccessToken, error) {
	return m.tokenEncoder.DecodeAccessToken(token)
}

func containsGrantType(allowed []model.OAuthGrantType, expected model.OAuthGrantType) bool {
	for _, v := range allowed {
		if v == expected {
			return true
		}
	}
	return false
}
