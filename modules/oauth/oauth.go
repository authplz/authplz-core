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
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"log"
	"time"
)

import (
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/compose"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

const OAuthSecretBytes int = 64

// Config structure
type Config struct {
	Key *rsa.PrivateKey // Private key for OAuth token attestation
}

// Controller OAuth module controller
type Controller struct {
	OAuth2 fosite.OAuth2Provider
	store  Storer
}

func init() {
	// Register AuthorizeRequests for session serialisation
	gob.Register(&fosite.AuthorizeRequest{})
}

// NewController Creates a new OAuth2 controller instance
func NewController(store Storer) (*Controller, error) {

	// Create configuration
	var oauthConfig = &compose.Config{
		AccessTokenLifespan: time.Minute * 30,
	}

	secret := []byte("some-super-cool-secret-that-nobody-knows")
	// Create OAuth2 and OpenID Strategies
	var strat = compose.CommonStrategy{
		CoreStrategy: compose.NewOAuth2HMACStrategy(oauthConfig, secret),
		//CoreStrategy: compose.NewOAuth2JWTStrategy(cfg.Key),
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

	return &Controller{oauth2, store}, nil
}

func generateSecret(len int) (string, error) {
	data := make([]byte, len)
	n, err := rand.Read(data)
	if err != nil {
		return "", err
	}
	if n != len {
		return "", errors.New("Config: RNG failed")
	}

	return base64.URLEncoding.EncodeToString(data), nil
}

func (oc *Controller) Fake() {

}

// Create an OAuth authorization code grant based client for a given user
// This is used to authenticate first party applications that can store client information
func (oc *Controller) CreateAuthorization(clientId string, userId string, scope string, redirect string) (*Client, error) {

	return nil, nil
}

// Create an OAuth implicit grant based client for a given user
// This is used to authenticate web services (or other services without persistence)
func (oc *Controller) CreateImplicit(clientId string, userId string, scope string, redirect string) (Client, error) {

	return nil, nil
}

// CreateClient Creates an OAuth Client Credential grant based client for a given user
// This is used to authenticate simple devices and must be pre-created
func (oc *Controller) CreateClient(userID string, scopes, redirects, grantTypes, responseTypes string, public bool) (*ClientResp, error) {

	// Generate Client ID and Secret
	clientID := uuid.NewV4().String()
	clientSecret, err := generateSecret(OAuthSecretBytes)
	if err != nil {
		return nil, err
	}

	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(clientSecret), 14)
	if err != nil {
		return nil, err
	}

	// TODO: check redirect is valid

	// TODO: check grant / response types are valid

	// Add to store
	c, err := oc.store.AddClient(userID, clientID, string(hashedSecret), scopes, redirects, grantTypes, responseTypes, public)
	if err != nil {
		return nil, err
	}

	client := c.(Client)

	resp := ClientResp{
		ClientID:     client.GetID(),
		CreatedAt:    client.GetCreatedAt(),
		LastUsed:     client.GetLastUsed(),
		Scopes:       client.GetScopes(),
		RedirectURIs: client.GetRedirectURIs(),
		UserData:     client.GetUserData(),
		Secret:       clientSecret,
	}

	return &resp, nil
}

// ClientResp is the object returned by client requests
type ClientResp struct {
	ClientID     string
	CreatedAt    time.Time
	LastUsed     time.Time
	Scopes       []string
	RedirectURIs []string
	UserData     interface{}
	Secret       string
}

func (oc *Controller) NewSession(username, subject string) (*UserSession, error) {
	return nil, nil
}

// GetClients Fetch clients for a given user id
func (oc *Controller) GetClients(userID string) ([]ClientResp, error) {
	clientResps := make([]ClientResp, 0)

	clients, err := oc.store.GetClientsByUserID(userID)
	if err != nil {
		return clientResps, err
	}

	for _, c := range clients {
		client := c.(Client)

		clean := ClientResp{
			ClientID:     client.GetID(),
			CreatedAt:    client.GetCreatedAt(),
			LastUsed:     client.GetLastUsed(),
			Scopes:       client.GetScopes(),
			RedirectURIs: client.GetRedirectURIs(),
			UserData:     client.GetUserData(),
		}

		clientResps = append(clientResps, clean)
	}

	return clientResps, nil
}

func (oc *Controller) UpdateClient(client Client) error {
	_, err := oc.store.UpdateClient(&client)
	return err
}

func (oc *Controller) RemoveClient(clientId string) error {
	return oc.store.RemoveClientByID(clientId)
}

type AccessResponse struct {
	RequestedAt time.Time
	ExpiresAt   time.Time
}

func (oc *Controller) GetAccessToken(tokenString string) (*AccessResponse, error) {
	a, err := oc.store.GetAccessTokenSession(tokenString)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, nil
	}

	log.Printf("Fetching access token %+v", a)

	access := a.(AccessTokenSession)

	ar := AccessResponse{
		RequestedAt: access.GetRequestedAt(),
		ExpiresAt:   access.GetExpiresAt(),
	}

	return &ar, nil
}

func (oc *Controller) Authorize() {

}
