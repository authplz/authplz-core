package datastore

import "time"

// Oauth client application
type OauthClientApp struct {
	ID          uint      `gorm:"primary_key" description:"External user ID"`
	CreatedAt   time.Time `gorm:"not null"`
	UpdatedAt   time.Time
	DeletedAt   *time.Time
	ExtId       string `gorm:"not null;unique"`
	Secret      string `gorm:"not null;unique"`
	RedirectUri string `gorm:"not null"`
}

// Getters and Setters
func (oc *OauthClientApp) GetId() string            { return oc.ExtId }
func (oc *OauthClientApp) GetSecret() string        { return oc.Secret }
func (oc *OauthClientApp) GetRedirectUri() string   { return oc.RedirectUri }
func (oc *OauthClientApp) GetUserData() interface{} { return nil }
