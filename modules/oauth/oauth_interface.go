package oauth

import (
	"time"
)

// Client OAuth client interface
type Client interface {
	// Client id
	GetId() string

	// Client secret
	GetSecret() string

	// Base client uri
	GetRedirectUri() string

	// Data to be passed to storage. Not used by the library.
	GetUserData() interface{}
}

type Authorizaton interface {
	GetClientID() string
	GetCode() string
	GetExpiresIn() uint32
	GetScope() string
	GetRedirectUri() string
	GetState() string
	GetCreatedAt() time.Time
}

// Storer OAuth storage interface
type Storer interface {
	AddClient(userID, clientID, secret, scope, redirect string) (interface{}, error)
	GetClientByID(clientID string) (interface{}, error)
	GetClientsByUserID(userID string) ([]interface{}, error)
	RemoveClientByID(clientID string) error
	AddAuthorization(clientID, code string, expires int32, scope, redirect, state string) (interface{}, error)
	GetAuthorizationByCode(code string) (interface{}, error)
}
