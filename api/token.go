// Defines messages and types for token handler implementations

package api

import (
    "errors"
)

// Token action type for interface
type TokenAction string

// Token success actions
const TokenActionActivate TokenAction   = "activate"
const TokenActionUnlock  TokenAction    = "unlock"

// Token error actions
const TokenActionInvalid TokenAction    = "invalid"
const TokenActionExpired TokenAction    = "expired"

var TokenError                          = errors.New("internal server error")
var TokenErrorInvalidUser               = errors.New("invalid user")
