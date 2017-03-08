package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"time"
)

import (
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/compose"
	"github.com/ory-am/fosite/handler/openid"
	"github.com/ory-am/fosite/token/jwt"
	//	"github.com/satori/go.uuid"
	//	"golang.org/x/crypto/bcrypt"
)

const OAuthSecretBytes int = 64

// Config structure
type Config struct {
	Key *rsa.PrivateKey // Private key for OAuth token attestation
}

// Controller OAuth module controller
type Controller struct {
	OAuth2 fosite.OAuth2Provider
	Store  Storer
}

// Create a new OAuth server instance
func NewController(cfg Config, store Storer) (*Controller, error) {

	// Register required objects for session serialisation
	gob.Register(&fosite.AuthorizeRequest{})

	// Create config instance
	config := new(compose.Config)

	storerAdaptor := NewAdaptor(store)

	// Create OAuth2 and OpenID Strategies
	var strat = compose.CommonStrategy{
		CoreStrategy: compose.NewOAuth2HMACStrategy(config, []byte("some-super-cool-secret-that-nobody-knows")),
		//CoreStrategy: compose.NewOAuth2JWTStrategy(cfg.Key),
		//OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(cfg.Key),
	}

	// Compose oauth server from components
	var oauth2 = compose.Compose(
		config,
		storerAdaptor,
		strat,

		// enabled handlers
		//compose.OAuth2AuthorizeExplicitFactory,
		//compose.OAuth2AuthorizeImplicitFactory,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		//compose.OAuth2ResourceOwnerPasswordCredentialsFactory,

		//compose.OAuth2TokenRevocationFactory,
		compose.OAuth2TokenIntrospectionFactory,

		//compose.OpenIDConnectExplicitFactory,
		//compose.OpenIDConnectImplicitFactory,
		//compose.OpenIDConnectHybridFactory,
	)

	// Return OAuth controller instance
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

func (oc *Controller) NewSession(extId string) *openid.DefaultSession {
	return &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Issuer:    "https://fosite.my-application.com",
			Subject:   extId,
			Audience:  "https://my-client.my-application.com",
			ExpiresAt: time.Now().Add(time.Hour * 6),
			IssuedAt:  time.Now(),
		},
		Headers: &jwt.Headers{
			Extra: make(map[string]interface{}),
		},
	}
}

// Create an OAuth authorization code grant based client for a given user
// This is used to authenticate first party applications that can store client information
func (oc *Controller) CreateAuthorization(clientId string, userId string, scope string, redirect string) (*OauthClient, error) {

	return nil, nil
}

// Create an OAuth implicit grant based client for a given user
// This is used to authenticate web services (or other services without persistence)
func (oc *Controller) CreateImplicit(clientId string, userId string, scope string, redirect string) (*OauthClient, error) {

	return nil, nil
}
