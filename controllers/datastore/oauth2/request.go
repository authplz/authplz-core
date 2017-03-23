package oauth

import (
	"strings"
	"time"
)

// OauthRequest Base Type
// This is not stored directly, but used in other oauth types
type OauthRequest struct {
	RequestID string
	//Client        OauthClient `sql:"-"`
	RequestedAt   time.Time
	ExpiresAt     time.Time
	Scopes        string
	GrantedScopes string
	Form          string
	//Session       OauthSession `sql:"-"`
}

// Getters and Setters

func (or OauthRequest) GetRequestedAt() time.Time { return or.RequestedAt }

func (or OauthRequest) GetExpiresAt() time.Time { return or.ExpiresAt }

func (c OauthRequest) GetGrantedScopes() []string {
	return strings.Split(c.GrantedScopes, ";")
}

func (c OauthRequest) GetScopes() []string {
	return strings.Split(c.Scopes, ";")
}
