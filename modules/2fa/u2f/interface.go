package u2f

import (
	"time"
)

// Token instance interface
// This must be implemented by the token storage implementation
type U2FTokenInterface interface {
	GetName() string
	GetKeyHandle() string
	GetPublicKey() string
	GetCertificate() string
	GetCounter() uint
	SetCounter(uint)
	GetLastUsed() time.Time
	SetLastUsed(time.Time)
}

// Token store interface
// This must be implemented by a storage module to provide persistence to the module
type U2FStoreInterface interface {
	// Fetch a user instance by user id (should be able to remove this)
	GetUserByExtId(userid string) (interface{}, error)
	// Add a fido token to a given user
	AddFidoToken(userid, name, keyHandle, publicKey, certificate string, counter uint) (interface{}, error)
	// Fetch fido tokens for a given user
	GetFidoTokens(userid string) ([]interface{}, error)
	// Update a provided fido token
	UpdateFidoToken(token interface{}) (interface{}, error)
}
