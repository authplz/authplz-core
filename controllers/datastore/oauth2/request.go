package oauth

import (
	"time"
)

import (
//	"github.com/jinzhu/gorm"
)

// Oauth Request Base Type
type OauthRequest struct {
	RequestID     string
	Client        OauthClient `sql:"-"`
	RequestedAt   time.Time
	Scopes        string
	GrantedScopes string
	Form          string
	Session       OauthSession `sql:"-"`
}

// Getters and Setters
