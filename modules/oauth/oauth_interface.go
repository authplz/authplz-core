package oauth

import (
	"time"
)

// Client OAuth client application interface
type Client interface {
	GetID() string
	GetSecret() string
	GetRedirectURIs() []string
	GetUserData() interface{}
	GetScopes() []string
	GetGrantTypes() []string
	GetResponseTypes() []string
	IsPublic() bool
	GetCreatedAt() time.Time
	GetLastUsed() time.Time
	SetLastUsed(time.Time)
}

// AuthorizeCodeSession is an OAuth Authorization Code Grant Session
type AuthorizeCodeSession interface {
	GetUserID() string
	GetCode() string
	GetScopes() []string
	GetRequestedAt() time.Time
	GetExpiresAt() time.Time
}

// RefreshTokenSession is an OAuth Refresh Token Session
type RefreshTokenSession interface {
	GetUserID() string
	GetSignature() string
	GetScopes() []string
	GetRequestedAt() time.Time
	GetExpiresAt() time.Time
}

// AccessTokenSession is an OAuth Access Token Session
type AccessTokenSession interface {
	GetUserID() string
	GetSignature() string
	GetScopes() []string
	GetRequestedAt() time.Time
	GetExpiresAt() time.Time
}

// UserSession is user data associated with an OAuth session
type UserSession interface {
	GetUserID() string
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
// This must be implemented by the underlying storage device
type Storer interface {
	// Client (application) storage
	AddClient(userID, clientID, secret, scopes, redirects, grants, responseTypes string, public bool) (interface{}, error)
	GetClientByID(clientID string) (interface{}, error)
	GetClientsByUserID(userID string) ([]interface{}, error)
	UpdateClient(client interface{}) (interface{}, error)
	RemoveClientByID(clientID string) error

	// OAuth User Session Storage

	// Authorization code storage
	AddAuthorizeCodeSession(userID, clientID, code, requestID string, requestedAt, expiresAt time.Time, scopes, grantedScopes []string) (interface{}, error)
	GetAuthorizeCodeSession(code string) (interface{}, error)
	GetAuthorizeCodeSessionByRequestID(requestID string) (interface{}, error)
	RemoveAuthorizeCodeSession(code string) error

	// Access Token storage
	AddAccessTokenSession(userID, clientID, signature, requestID string, requestedAt, expiresAt time.Time,
		scopes, grantedScopes []string) (interface{}, error)
	GetAccessTokenSession(sgnature string) (interface{}, error)
	GetClientByAccessTokenSession(token string) (interface{}, error)
	GetAccessTokenSessionByRequestID(requestID string) (interface{}, error)
	RemoveAccessTokenSession(token string) error

	// Refresh token storage
	AddRefreshTokenSession(userID, clientID, signature, requestID string, requestedAt, expiresAt time.Time, scopes, grantedScopes []string) (interface{}, error)
	GetRefreshTokenBySignature(signature string) (interface{}, error)
	GetRefreshTokenSessionByRequestID(requestID string) (interface{}, error)
	RemoveRefreshToken(signature string) error
}
