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
	"bytes"
	"crypto/rsa"
	"encoding/gob"
	"log"
	"regexp"
	"text/template"
	"time"
)

import (
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/compose"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
	"strings"
)

const OAuthSecretBytes int = 64

var GrantTypes = []string{"implicit", "explicit", "code", "client_credentials"}
var ClientScopes = []string{"user"}

// Config structure
type Config struct {
	Key            *rsa.PrivateKey // Private key for OAuth token attestation
	ScopeMatcher   string          // Regex expression for validating scopes
	ScopeValidator string          // Template that must be matched as a prefix for a valid scope
}

// Controller OAuth module controller
type Controller struct {
	OAuth2         fosite.OAuth2Provider
	store          Storer
	scopeMatcher   *regexp.Regexp
	scopeValidator *template.Template
}

func init() {
	// Register AuthorizeRequests for session serialisation
	gob.Register(&fosite.AuthorizeRequest{})
}

// NewController Creates a new OAuth2 controller instance
func NewController(store Storer, config Config) (*Controller, error) {

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

	scopeMatcher, err := regexp.Compile(config.ScopeMatcher)
	if err != nil {
		return nil, err
	}

	scopeValidator, err := template.New("runner").Parse(config.ScopeValidator)
	if err != nil {
		return nil, err
	}

	c := Controller{
		OAuth2:         oauth2,
		store:          store,
		scopeMatcher:   scopeMatcher,
		scopeValidator: scopeValidator,
	}

	return &c, nil
}

// ValidateScopes enforces scope rules from the configuration
func (oc *Controller) ValidateScopes(username string, scopes []string) []string {
	granted := make([]string, 0)

	for _, s := range scopes {
		// Check scope matches regex matcher
		if matches := oc.scopeMatcher.MatchString(s); !matches {
			continue
		}

		// Check scope matches template validator
		data := make(map[string]string)
		data["username"] = username

		// Generate validator from session
		var buf bytes.Buffer
		err := oc.scopeValidator.Execute(&buf, data)
		if err != nil {
			continue
		}

		// Append to granted if the validator matches
		if strings.HasPrefix(s, buf.String()) {
			granted = append(granted, s)
		}
	}

	return granted
}

// CreateExplicit Create an OAuth explicit authorization code grant based client for a given user
// This is used to authenticate first party applications that can store client information
func (oc *Controller) CreateExplicit(clientID string, userID string, scopes, redirects []string) (*Client, error) {

	return nil, nil
}

// CreateImplicit Creates an OAuth implicit grant based client for a given user
// This is used to authenticate web services (or other services without persistence)
func (oc *Controller) CreateImplicit(clientID string, userID string, scopes, redirects []string) (Client, error) {

	return nil, nil
}

// CreateClient Creates an OAuth Client Credential grant based client for a given user
// This is used to authenticate simple devices and must be pre-created
func (oc *Controller) CreateClient(userID string, scopes, redirects, grantTypes, responseTypes []string, public bool) (*ClientResp, error) {

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
	Secret       string
}

// GetClients Fetch clients owned by a given user
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
		}

		clientResps = append(clientResps, clean)
	}

	return clientResps, nil
}

// UpdateClient Update a client instance
func (oc *Controller) UpdateClient(client Client) error {
	_, err := oc.store.UpdateClient(&client)
	return err
}

// RemoveClient Removes a client instance
func (oc *Controller) RemoveClient(clientId string) error {
	return oc.store.RemoveClientByID(clientId)
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
		return nil, err
	}
	if a == nil {
		return nil, nil
	}

	log.Printf("Fetching access token %+v", a)

	access := a.(AccessTokenSession)

	ar := AccessTokenInfo{
		RequestedAt: access.GetRequestedAt(),
		ExpiresAt:   access.GetExpiresAt(),
	}

	return &ar, nil
}
