package oauth

import (
	"time"
)

import (
	"github.com/jinzhu/gorm"
)

// Session session storage
type OauthSession struct {
	gorm.Model
	Username        string
	Subject         string
	AccessExpiry    time.Time
	RefreshExpiry   time.Time
	AuthorizeExpiry time.Time
	IDExpiry        time.Time
}

// Getters and Setters
func NewSession() OauthSession {
	return OauthSession{
		AccessExpiry:    time.Time{},
		RefreshExpiry:   time.Time{},
		AuthorizeExpiry: time.Time{},
		IDExpiry:        time.Time{},
	}
}
