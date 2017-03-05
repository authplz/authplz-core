/*
 * TOTP Module interfaces
 * This defines the interfaces required to use the TOTP module
 *
 * AuthEngine Project (https://github.com/ryankurte/authengine)
 * Copyright 2017 Ryan Kurte
 */

package totp

import (
	"time"
)

// TokenInterface Token instance interface
// This must be implemented by the token storage implementation
type TokenInterface interface {
	GetName() string
	GetSecret() string
	GetCounter() uint
	SetCounter(uint)
	GetLastUsed() time.Time
	SetLastUsed(time.Time)
}

// Storer Token store interface
// This must be implemented by a storage module to provide persistence to the module
type Storer interface {
	// Fetch a user instance by user id (should be able to remove this)
	GetUserByExtId(userid string) (interface{}, error)
	// Add a fido token to a given user
	AddTotpToken(userid, name, secret string, counter uint) (interface{}, error)
	// Fetch fido tokens for a given user
	GetTotpTokens(userid string) ([]interface{}, error)
	// Update a provided fido token
	UpdateTotpToken(token interface{}) (interface{}, error)
}
