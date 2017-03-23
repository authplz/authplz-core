package oauth

import (
	"strings"
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
	return strings.Split(c.GrantedScopes, ";")
}

func (c OauthRequest) GetScopes() []string {
	return strings.Split(c.Scopes, ";")
}

func (c OauthRequest) SetGrantedScopes(scopes []string) {
	c.Scopes = strings.Join(scopes, ";")
}

func (c OauthRequest) SetScopes(scopes []string) {
	c.GrantedScopes = strings.Join(scopes, ";")
}
