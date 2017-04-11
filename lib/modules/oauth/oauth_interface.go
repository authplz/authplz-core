/*
 * OAuth Module Interfaces
 * Defines interfaces required by the OAuth module
 *
 * AuthPlz Project (https://github.com/ryankurte/AuthPlz)
 * Copyright 2017 Ryan Kurte
 */

package oauth

import (
	"time"
)

// User OAuth user interface
type User interface {
	GetExtID() string
	IsAdmin() bool
}

// Client OAuth client application interface
type Client interface {
	GetID() string
	GetName() string
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

// SessionBase defines the common interface across all OAuth sessions
type SessionBase interface {
	GetClient() interface{}
	GetSession() interface{}
	SetSession(session interface{})

	GetRequestID() string
	GetUserID() string

	GetRequestedAt() time.Time
	GetExpiresAt() time.Time

	GetRequestedScopes() []string
	SetRequestedScopes(scopes []string)
	AppendRequestedScope(scope string)

	GetGrantedScopes() []string
	GrantScope(scope string)

	Merge(interface{})
}

// AuthorizeCodeSession is an OAuth Authorization Code Grant Session
type AuthorizeCodeSession interface {
	SessionBase
	GetCode() string
}

// RefreshTokenSession is an OAuth Refresh Token Session
type RefreshTokenSession interface {
	SessionBase
	GetSignature() string
}

// AccessTokenSession is an OAuth Access Token Session
type AccessTokenSession interface {
	SessionBase
	GetSignature() string
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

	Clone() interface{}
}

// Storer OAuth storage interface
// This must be implemented by the underlying storage device
type Storer interface {
	// User storage
	GetUserByExtID(userid string) (interface{}, error)

	// Client (application) storage
	AddClient(userID, clientID, clientName, secret string, scopes, redirects, grantTypes, responseTypes []string, public bool) (interface{}, error)
	GetClientByID(clientID string) (interface{}, error)
	GetClientsByUserID(userID string) ([]interface{}, error)
	UpdateClient(client interface{}) (interface{}, error)
	RemoveClientByID(clientID string) error

	// OAuth User Session Storage

	// Authorization code storage
	AddAuthorizeCodeSession(userID, clientID, code, requestID string, requestedAt, expiresAt time.Time, scopes, grantedScopes []string) (interface{}, error)
	GetAuthorizeCodeSession(code string) (interface{}, error)
	GetAuthorizeCodeSessionByRequestID(requestID string) (interface{}, error)
	GetAuthorizeCodeSessionsByUserID(userID string) ([]interface{}, error)
	RemoveAuthorizeCodeSession(code string) error

	// Access Token storage
	AddAccessTokenSession(userID, clientID, signature, requestID string, requestedAt, expiresAt time.Time,
		scopes, grantedScopes []string) (interface{}, error)
	GetAccessTokenSession(sgnature string) (interface{}, error)
	GetClientByAccessTokenSession(token string) (interface{}, error)
	GetAccessTokenSessionByRequestID(requestID string) (interface{}, error)
	GetAccessTokenSessionsByUserID(userID string) ([]interface{}, error)
	RemoveAccessTokenSession(token string) error

	// Refresh token storage
	AddRefreshTokenSession(userID, clientID, signature, requestID string, requestedAt, expiresAt time.Time, scopes, grantedScopes []string) (interface{}, error)
	GetRefreshTokenBySignature(signature string) (interface{}, error)
	GetRefreshTokenSessionByRequestID(requestID string) (interface{}, error)
	GetRefreshTokenSessionsByUserID(userID string) ([]interface{}, error)
	RemoveRefreshToken(signature string) error
}
