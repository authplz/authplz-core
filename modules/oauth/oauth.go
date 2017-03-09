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
	"github.com/RangelReale/osin"
	"github.com/satori/go.uuid"
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
	Server *osin.Server
	Store  Storer
}

func init() {
	// Register AuthorizeRequests for session serialisation
	gob.Register(&osin.AuthorizeRequest{})
}

// Create a new OAuth server instance
func NewController(store Storer) (*Controller, error) {

	// Create configuration
	cfg := osin.NewServerConfig()

	// Allow token authorization only
	cfg.AllowedAuthorizeTypes = osin.AllowedAuthorizeType{osin.CODE, osin.TOKEN}

	// Allow access via authorization code, client credentials (devices) with refresh tokens
	cfg.AllowedAccessTypes = osin.AllowedAccessType{
		osin.AUTHORIZATION_CODE, osin.REFRESH_TOKEN, osin.CLIENT_CREDENTIALS}

	cfg.AllowGetAccessRequest = true
	cfg.AllowClientSecretInParams = true

	// Create server object
	server := osin.NewServer(cfg, store)

	return &Controller{server, store}, nil
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
func (oc *Controller) CreateImplicit(clientId string, userId string, scope string, redirect string) (*Client, error) {

	return nil, nil
}

// CreateClient Creates an OAuth Client Credential grant based client for a given user
// This is used to authenticate simple devices and must be pre-created
func (oc *Controller) CreateClient(userId string, scope string, redirect string) (*Client, error) {

	// Generate Client ID and Secret
	clientId := uuid.NewV4().String()
	clientSecret, err := generateSecret(OAuthSecretBytes)
	if err != nil {
		return nil, err
	}

	// TODO: check redirect is valid

	// Add to store
	client, err = oc.Store.AddClient(userId, clientId, clientSecret, scope, redirect)
	if err != nil {
		return nil, err
	}

	// Full client instance is only returned once (at creation)
	// Following this, secret will not be returned
	return client, nil
}

// ClientResp is the object returned by client requests
type ClientResp struct {
	ClientID    string
	CreatedAt   time.Time
	LastUsed    time.Time
	Scope       string
	RedirectUri string
	UserData    interface{}
}

// GetClients Fetch clients for a given user id
func (oc *Controller) GetClients(userID string) ([]ClientResp, error) {
	clientResps := make([]ClientResp, 0)

	clients, err := oc.Store.GetClientsByUser(userID)
	if err != nil {
		return clientResps, err
	}

	for _, c := range clients {
		client := c.(Client)

		clean := ClientResp{
			ClientID:    c.GetClientID(),
			CreatedAt:   c.GetCreatedAt(),
			LastUsed:    c.GetLastUsed(),
			Scope:       c.GetScope(),
			RedirectUri: c.GetRedirectUri(),
			UserData:    c.GetUserData(),
		}

		clientResps = append(clientResps, clean)
	}

	return clientResps, nil
}

func (oc *Controller) RemoveClient(clientId string) error {
	return oc.Store.RemoveClient(clientId)
}

func (oc *Controller) Authorize() {

}
