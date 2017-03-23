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

type Refresh interface {
	GetSignature() string
	GetRequestedAt() time.Time
	GetExpiresAt() time.Time
}

type Access interface {
	GetSignature() string
	GetRequestedAt() time.Time
	GetExpiresAt() time.Time
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

	// Authorization code storage
	AddAuthorizeCodeSession(clientID, code, requestID string, requestedAt time.Time, scopes, grantedScopes []string) (interface{}, error)
	GetAuthorizeCodeSession(code string) (interface{}, error)
	GetAuthorizeCodeSessionByRequestID(requestID string) (interface{}, error)
	RemoveAuthorizeCodeSession(code string) error

	// Access Token storage
	AddAccessTokenSession(clientID, signature, requestID string, requestedAt time.Time,
		scopes, grantedScopes []string) (interface{}, error)
	GetAccessTokenSession(sgnature string) (interface{}, error)
	GetClientByAccessTokenSession(token string) (interface{}, error)
	GetAccessTokenSessionByRequestID(requestID string) (interface{}, error)
	RemoveAccessTokenSession(token string) error

	// Refresh token storage
	AddRefreshTokenSession(clientID, signature, requestID string, requestedAt time.Time, scopes, grantedScopes []string) (interface{}, error)
	GetRefreshTokenBySignature(signature string) (interface{}, error)
	GetRefreshTokenSessionByRequestID(requestID string) (interface{}, error)
	RemoveRefreshToken(signature string) error
}
