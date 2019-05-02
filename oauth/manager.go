package oauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/roberveral/oauth-server/utils"

	"github.com/roberveral/oauth-server/oauth/idp"
	"github.com/roberveral/oauth-server/oauth/model"
	"github.com/roberveral/oauth-server/oauth/repository"
	"github.com/roberveral/oauth-server/oauth/token"

	"github.com/google/uuid"
)

// authorizeHandler is the function signature that the handlers for the different
// response types in the OAuth Authorization phase must implement.
type authorizeHandler func(context.Context, *model.Client, *model.OAuthAuthorizeInput) (*model.OAuthAuthorizationCode, error)

// authorizeHandler is the function signature that the handlers for the different
// grant types in the OAuth Token exchange phase must implement.
type tokenHandler func(context.Context, *model.Client, *model.OAuthTokenInput) (*model.OAuthAccessToken, error)

type Manager struct {
	clientRepository    repository.ClientRepository
	identityProvider    idp.IdentityProvider
	authCodeRepository  repository.AuthorizationCodeRepository
	authCodeProvider    token.AuthorizationCodeProvider
	accessTokenProvider token.AccessTokenProvider
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
		RedirectURL:  input.RedirectURL,
		Owner:        user,
	}

	return m.clientRepository.StoreClient(ctx, client)
}

// Authorize performs the OAuth authorization request where a user (Resource Owner) grants
// authorization to a client to retrieve a token to act on his behalf. This step returns an
// authorization code which is sent to the client and can be used to obtain an access token.
func (m *Manager) Authorize(ctx context.Context, input *model.OAuthAuthorizeInput) (*model.OAuthAuthorizeResponse, error) {
	// Check that the authorized client exists
	client, err := m.GetClientByID(ctx, input.ClientID)
	if err != nil {
		return nil, err
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
	code, err := m.authCodeProvider.GenerateCode(authCode)
	if err != nil {
		return nil, err
	}

	response := &model.OAuthAuthorizeResponse{
		Code:        code,
		RedirectURL: fmt.Sprintf("%s?code=%s&state=%s", input.RedirectURI, code, input.State),
	}

	return response, nil
}

// Token performs the OAuth token request where a client request an access token to act on behalf of a
// user (Resource Owner who has authorized the application) or itself (depending on the grant_type). This
// step returns an access token which can be used to access resources in the Resource Servers.
func (m *Manager) Token(ctx context.Context, input *model.OAuthTokenInput) (*model.OAuthTokenResponse, error) {
	// Check that the client who requests a token exists.
	client, err := m.GetClientByID(ctx, input.ClientID)
	if err != nil {
		return nil, err
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
	encodedToken, err := m.accessTokenProvider.GenerateToken(accessToken)
	if err != nil {
		return nil, err
	}

	response := &model.OAuthTokenResponse{
		AccessToken: encodedToken,
		TokenType:   model.BearerTokenType,
		ExpiresIn:   3600,
	}

	return response, nil
}

// authCodeAuthorize is the handler for the 'authorize' of the Authorization Code flow.
// It generates an authorization code for the authorized client, including all the info required
// to validate the request to obtain an access token.
func (m *Manager) authCodeAuthorize(ctx context.Context, client *model.Client, input *model.OAuthAuthorizeInput) (*model.OAuthAuthorizationCode, error) {
	// If missing RedirectURI, use the provided during client registration
	redirectURI := input.RedirectURI
	if redirectURI == "" {
		redirectURI = client.RedirectURL
	} else if redirectURI != client.RedirectURL {
		return nil, &InvalidRedirectURIError{redirectURI, client.ClientID}
	}

	// Retrieve authenticated user (Resource Owner) who authorizes the client to act on
	// his behalf.
	user, ok := utils.GetAuthenticatedUserFromContext(ctx)
	if !ok {
		return nil, &UserNotAuthenticatedError{}
	}

	code := &model.OAuthAuthorizationCode{
		TokenID:        uuid.New().String(),
		UserID:         user,
		ClientID:       client.ClientID,
		RedirectURI:    redirectURI,
		ExpirationTime: time.Now().Add(10 * time.Second),
	}

	return code, nil
}

func (m *Manager) authCodeToken(ctx context.Context, client *model.Client, input *model.OAuthTokenInput) (*model.OAuthAccessToken, error) {
	code, err := m.authCodeProvider.ValidateCode(input.Code)
	if err != nil {
		return nil, err
	}

	if code.ClientID != client.ClientID || code.RedirectURI != input.RedirectURI {
		return nil, errors.New("authorization code not valid for this client_id")
	}

	if input.ClientSecret != client.ClientSecret {
		return nil, errors.New("invalid client_secret")
	}

	if code.ExpirationTime.Before(time.Now()) {
		return nil, errors.New("expired authorization code")
	}

	alreadyUsed, err := m.authCodeRepository.CheckAuthorizationCodeByID(ctx, code.TokenID)
	if err != nil {
		return nil, err
	}

	if alreadyUsed {
		return nil, errors.New("authorization_code already used")
	}

	user, err := m.identityProvider.GetUserByID(ctx, code.UserID)
	if err != nil {
		return nil, err
	}

	accessToken := &model.OAuthAccessToken{
		ClientID:       client.ClientID,
		ExpirationTime: time.Now().Add(3 * time.Hour),
		User:           user,
	}

	if err = m.authCodeRepository.StoreUsedAuthorizationCode(ctx, code); err != nil {
		return nil, err
	}

	return accessToken, nil
}
