package token

import (
	"time"
)

// Token defines the interface required for stored tokens
type Token interface {
	GetTokenID() string
	GetUserExtID() string
	GetAction() string
	IsUsed() bool
	GetExpiry() time.Time
	SetUsed(t time.Time)
}

// Storer defines the backing storage required by the token controller
type Storer interface {
	CreateActionToken(userID, tokenID, action string, expiry time.Time) (interface{}, error)
	GetActionToken(tokenID string) (interface{}, error)
	UpdateActionToken(token interface{}) (interface{}, error)
}
