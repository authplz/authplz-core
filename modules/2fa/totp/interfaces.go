/*
 * TOTP Module API interfaces
 * This defines the interfaces required to use the TOTP module
 *
 * AuthEngine Project (https://github.com/ryankurte/authengine)
 * Copyright 2017 Ryan Kurte 
 */


package u2f

import (
    "time"
)

// Token instance interface
// This must be implemented by the token storage implementation
type TotpTokenInterface interface {
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
type TotpStoreInterface interface {
    // Fetch a user instance by user id (should be able to remove this)
    GetUserByExtId(userid string) (interface{}, error)
    // Add a fido token to a given user
    AddTotpToken(userid, name, secret string, counter uint) (interface{}, error)
    // Fetch fido tokens for a given user
    GetTotpTokens(userid string) ([]interface{}, error)
    // Update a provided fido token
    UpdateTotpToken(token interface{}) (interface{}, error)
}
