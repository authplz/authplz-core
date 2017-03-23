package oauth

import (
	"time"
)

import (
	"github.com/jinzhu/gorm"
)

// OauthRefresh Refresh token storage
type OauthRefresh struct {
	gorm.Model
	Username        string
	Subject         string
	AccessExpiry    time.Time
	RefreshExpiry   time.Time
	AuthorizeExpiry time.Time
	IDExpiry        time.Time
}
