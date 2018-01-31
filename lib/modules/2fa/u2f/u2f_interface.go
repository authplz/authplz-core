/*
 * U2F / Fido Module API interfaces
 * This defines the interfaces required to use the u2f module
 *
 * AuthPlz Project (https://github.com/authplz/authplz-core)
 * Copyright 2017 Ryan Kurte
 */

package u2f

import (
	"time"
)

// TokenInterface Token instance interface
// This must be implemented by the token storage implementation
type TokenInterface interface {
	GetExtID() string
	GetName() string
	GetKeyHandle() string
	GetPublicKey() string
	GetCertificate() string
	GetCounter() uint
	SetCounter(uint)
	GetLastUsed() time.Time
	SetLastUsed(time.Time)
}

// Storer U2F Token store interface
// This must be implemented by a storage module to provide persistence to the module
type Storer interface {
	// Fetch a user instance by user id (should be able to remove this)
	GetUserByExtID(userid string) (interface{}, error)
	// Add a fido token to a given user
	AddFidoToken(userid, name, keyHandle, publicKey, certificate string, counter uint) (interface{}, error)
	// Fetch fido tokens for a given user
	GetFidoTokens(userid string) ([]interface{}, error)
	// Update a provided fido token
	UpdateFidoToken(token interface{}) (interface{}, error)
	// Remove the provided fido token
	RemoveFidoToken(token interface{}) error
}

// CompletedHandler Callback for 2fa signature completion
type CompletedHandler interface {
	SecondFactorCompleted(userid, action string)
}
