/*
 * OAuth Module Controller
 * This manages OAuth registration/alteration/revocation
 *
 * AuthEngine Project (https://github.com/ryankurte/authengine)
 * Copyright 2017 Ryan Kurte
 */

// TODO: move all database operations and things into the controller.

package oauth

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/compose"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

import ()

const (
	//OAuthSecretBytes is the length of OAuth secrets
	OAuthSecretBytes int = 128
)

// ErrInternal indicates an internal error in the OAuth controller
// This is a safe error return for the OAuth API to wrap underlying errors
var ErrInternal = errors.New("OAuth internal error")

// Config OAuth controller coniguration structure
type Config struct {
	TokenSecret string // Private key for OAuth token attestation
}

// Controller OAuth module controller
type Controller struct {
	OAuth2 fosite.OAuth2Provider
	store  Storer
}

// NewController Creates a new OAuth2 controller instance
func NewController(store Storer, config Config) (*Controller, error) {

	// Create configuration
	var oauthConfig = &compose.Config{
		AccessTokenLifespan:   time.Minute * 30,
		AuthorizeCodeLifespan: time.Hour * 24 * 365,
		IDTokenLifespan:       time.Hour * 24 * 28,
	}

	// Create OAuth2 and OpenID Strategies
	var strat = compose.CommonStrategy{
		CoreStrategy: compose.NewOAuth2HMACStrategy(oauthConfig, []byte(config.TokenSecret)),
		//OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(cfg.Key),
	}

	wrappedStore := NewAdaptor(store)

	var oauth2 = compose.Compose(
		oauthConfig,
		wrappedStore,
		strat,

		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2AuthorizeImplicitFactory,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2RefreshTokenGrantFactory,

		compose.OAuth2TokenRevocationFactory,
		compose.OAuth2TokenIntrospectionFactory,

		//compose.OpenIDConnectExplicitFactory,
		//compose.OpenIDConnectImplicitFactory,
		//compose.OpenIDConnectHybridFactory,
	)

	c := Controller{
		OAuth2: oauth2,
		store:  store,
	}

	return &c, nil
}

var AdminGrantTypes = []string{"implicit", "explicit", "code", "client_credentials"}
var UserGrantTypes = []string{"implicit", "client_credentials"}

var AdminClientScopes = []string{"public", "private", "introspect"}
var UserClientScopes = []string{"public", "private"}

// CreateClient Creates an OAuth Client Credential grant based client for a given user
// This is used to authenticate simple devices and must be pre-created
func (oc *Controller) CreateClient(userID string, scopes, redirects, grantTypes, responseTypes []string, public bool) (*ClientResp, error) {

	// Fetch the associated user account
	u, err := oc.store.GetUserByExtID(userID)
	if err != nil {
		log.Printf("OAuthController.CreateClient error fetching user: %s", err)
		return nil, ErrInternal
	}
	user := u.(User)

	// Generate Client ID and Secret
	clientID := uuid.NewV4().String()
	clientSecret, err := generateSecret(OAuthSecretBytes)
	if err != nil {
		log.Printf("OAuthController.CreateClient error generating client secret: %s", err)
		return nil, ErrInternal
	}
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(clientSecret), 14)
	if err != nil {
		log.Printf("OAuthController.CreateClient error generating secret hash: %s", err)
		return nil, ErrInternal
	}

	// TODO: should we be checking redirects are valid?

	// Check scopes are valid
	for _, s := range scopes {
		if user.IsAdmin() {
			if !fosite.HierarchicScopeStrategy(AdminClientScopes, s) {
				return nil, fmt.Errorf("Invalid client scope: %s (allowed: %s)", s, strings.Join(AdminClientScopes, ", "))
			}
		} else {
			if !fosite.HierarchicScopeStrategy(UserClientScopes, s) {
				return nil, fmt.Errorf("Invalid client scope: %s (allowed: %s)", s, strings.Join(UserClientScopes, ", "))
			}
		}
	}

	// Check grant / response types are valid
	for _, g := range grantTypes {
		if user.IsAdmin() {
			if !arrayContains(AdminGrantTypes, g) {
				return nil, fmt.Errorf("Invalid grant type: %s (allowed: %s)", g, strings.Join(AdminGrantTypes, ", "))
			}
		} else {
			if !arrayContains(UserGrantTypes, g) {
				return nil, fmt.Errorf("Invalid grant type: %s (allowed: %s)", g, strings.Join(UserGrantTypes, ", "))
			}
		}
	}

	// Add client to store
	c, err := oc.store.AddClient(userID, clientID, string(hashedSecret), scopes, redirects, grantTypes, responseTypes, public)
	if err != nil {
		log.Printf("OAuthController.CreateClient error saving client %s", err)
		return nil, ErrInternal
	}

	client := c.(Client)

	// Create API safe response instance
	// Note that this is the only time the client secret is available
	resp := ClientResp{
		ClientID:     client.GetID(),
		CreatedAt:    client.GetCreatedAt(),
		LastUsed:     client.GetLastUsed(),
		Scopes:       client.GetScopes(),
		GrantTypes:   client.GetGrantTypes(),
		RedirectURIs: client.GetRedirectURIs(),
		Secret:       clientSecret,
	}

	return &resp, nil
}

// ClientResp is the API safe object returned by client requests
type ClientResp struct {
	ClientID     string
	CreatedAt    time.Time
	LastUsed     time.Time
	Scopes       []string
	GrantTypes   []string
	RedirectURIs []string
	Secret       string
}

// GetClients Fetch clients owned by a given user
func (oc *Controller) GetClients(userID string) ([]ClientResp, error) {
	clientResps := make([]ClientResp, 0)

	clients, err := oc.store.GetClientsByUserID(userID)
	if err != nil {
		log.Printf("OAuthController.GetClients error fetching clients: %s", err)
		return clientResps, ErrInternal
	}

	for _, c := range clients {
		client := c.(Client)

		clean := ClientResp{
			ClientID:     client.GetID(),
			CreatedAt:    client.GetCreatedAt(),
			LastUsed:     client.GetLastUsed(),
			Scopes:       client.GetScopes(),
			GrantTypes:   client.GetGrantTypes(),
			RedirectURIs: client.GetRedirectURIs(),
		}

		clientResps = append(clientResps, clean)
	}

	return clientResps, nil
}

// UpdateClient Update a client instance
func (oc *Controller) UpdateClient(client Client) error {
	_, err := oc.store.UpdateClient(client)
	if err != nil {
		log.Printf("OAuthController.UpdateClient error updating client: %s", err)
		return ErrInternal
	}

	return nil
}

// RemoveClient Removes a client instance
func (oc *Controller) RemoveClient(clientID string) error {
	err := oc.store.RemoveClientByID(clientID)
	if err != nil {
		log.Printf("OAuthController.RemoveClient error removing client: %s", err)
		return ErrInternal
	}
	return nil
}

// AccessTokenInfo is an access token information response
type AccessTokenInfo struct {
	RequestedAt time.Time
	ExpiresAt   time.Time
}

// GetAccessTokenInfo fetches information for a provided access token
func (oc *Controller) GetAccessTokenInfo(tokenString string) (*AccessTokenInfo, error) {
	a, err := oc.store.GetAccessTokenSession(tokenString)
	if err != nil {
		log.Printf("OAuthController.GetAccessTokenInfo error fetching toke session: %s", err)
		return nil, ErrInternal
	}
	if a == nil {
		return nil, nil
	}

	access := a.(AccessTokenSession)

	ar := AccessTokenInfo{
		RequestedAt: access.GetRequestedAt(),
		ExpiresAt:   access.GetExpiresAt(),
	}

	return &ar, nil
}
