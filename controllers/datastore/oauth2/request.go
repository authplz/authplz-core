package oauthstore

import (
	"time"
)

// OauthRequest Base Type
// This is not stored directly, but used in other oauth types
type OauthRequest struct {
	RequestID     string
	RequestedAt   time.Time
	ExpiresAt     time.Time
	Scopes        string
	GrantedScopes string
	Form          string
	//Client        OauthClient `sql:"-"`
	//Session       OauthSession `sql:"-"`
}

// Getters and Setters

func (or OauthRequest) GetRequestedAt() time.Time {
	return or.RequestedAt
}

func (or OauthRequest) GetExpiresAt() time.Time {
	return or.ExpiresAt
}

func (c OauthRequest) GetGrantedScopes() []string {
	return stringToArray(c.GrantedScopes)
}

func (c OauthRequest) GetScopes() []string {
	return stringToArray(c.Scopes)
}

func (c OauthRequest) SetGrantedScopes(scopes []string) {
	c.Scopes = arrayToString(scopes)
}

func (c OauthRequest) SetScopes(scopes []string) {
	c.GrantedScopes = arrayToString(scopes)
}
