package datastore

import (
	"time"
)

import (
	"github.com/jinzhu/gorm"
)

// Oauth client application
type OauthClientApp struct {
	ID          uint      `gorm:"primary_key" description:"External user ID"`
	CreatedAt   time.Time `gorm:"not null"`
	UpdatedAt   time.Time
	DeletedAt   *time.Time
	ClientID    string `gorm:"not null;unique"`
	Secret      string `gorm:"not null;unique"`
	RedirectURI string `gorm:"not null"`
}

// Getters and Setters
func (oc *OauthClientApp) GetClientID() string      { return oc.ClientID }
func (oc *OauthClientApp) GetSecret() string        { return oc.Secret }
func (oc *OauthClientApp) GetRedirectURI() string   { return oc.RedirectURI }
func (oc *OauthClientApp) GetUserData() interface{} { return nil }

// GetClientByID an oauth client app by ClientID
func (dataStore *DataStore) GetClientByID(clientID string) (interface{}, error) {
	var client OauthClientApp
	err := dataStore.db.Where(&OauthClientApp{ClientID: clientID}).First(&client).Error
	if (err != nil) && (err != gorm.ErrRecordNotFound) {
		return nil, err
	} else if (err != nil) && (err == gorm.ErrRecordNotFound) {
		return nil, nil
	}

	return &client, nil
}
