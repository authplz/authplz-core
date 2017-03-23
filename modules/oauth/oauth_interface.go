package oauth

import (
	"time"
)

// Client OAuth client interface
type Client interface {
	// Client id
	GetID() string

	// Client secret
	GetSecret() string
	SetSecret(string)

	// Base client uri
	GetRedirectURIs() []string

	// Data to be passed to storage. Not used by the library.
	GetUserData() interface{}

	GetScopes() []string
	GetGrantTypes() []string
	GetResponseTypes() []string

	IsPublic() bool

	GetCreatedAt() time.Time
	GetLastUsed() time.Time
	SetLastUsed(time.Time)
}

type Authorizaton interface {
	GetClientID() string
	GetCode() string
	GetExpiresIn() int32
	GetScope() string
	GetRedirectUri() string
	GetState() string
	GetCreatedAt() time.Time
}

type Access interface {
	//GetClient() interface{}
	//GetClientID() string
	//GetAuthorizeData() interface{}
	//GetAccessData() interface{}
	//GetAccessToken() string
	//GetRefreshToken() string
	//GetExpiresIn() int32
	//GetScope() string
	//GetRedirectURI() string
	GetRequestedAt() time.Time
	GetExpiresAt() time.Time
	//GetUserData() interface{}
}

type Session interface {
	GetUsername() string
	GetSubject() string

	// Get and Set expiry times
	SetAccessExpiry(time.Time)
	GetAccessExpiry() time.Time
	SetRefreshExpiry(time.Time)
	GetRefreshExpiry() time.Time
	SetAuthorizeExpiry(time.Time)
	GetAuthorizeExpiry() time.Time
	SetIDExpiry(time.Time)
	GetIDExpiry() time.Time
}

// Storer OAuth storage interface
type Storer interface {
	AddClient(userID, clientID, secret, scopes, redirects, grants, responseTypes string, public bool) (interface{}, error)
	GetClientByID(clientID string) (interface{}, error)
	GetClientsByUserID(userID string) ([]interface{}, error)
	UpdateClient(client interface{}) (interface{}, error)
	RemoveClientByID(clientID string) error

	AddAuthorization(clientID, code string, expires int32, scope, redirect, state string) (interface{}, error)
	GetAuthorizationByCode(code string) (interface{}, error)
	RemoveAuthorizationByCode(code string) error

	// Access Token functions
	AddAccessTokenSession(clientID, signature, requestID string, requestedAt time.Time,
		scopes, grantedScopes, form string) (interface{}, error)
	GetAccessBySignature(sgnature string) (interface{}, error)
	GetClientByAccessToken(token string) (interface{}, error)
	RemoveAccessToken(token string) error

	// Refresh token functions
	AddRefreshTokenSession(clientID, signature, requestID string, requestedAt time.Time, scopes, grantedScopes []string) (interface{}, error)
	GetRefreshTokenBySignature(signature string) (interface{}, error)
	RemoveRefreshToken(signature string) error
}
