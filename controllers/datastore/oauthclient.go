package datastore

import (
	"time"
)

import (
	"github.com/jinzhu/gorm"
)

type OauthClient struct {
	ID          uint
	UserID      uint
	ClientID    string
	CreatedAt   time.Time
	LastUsed    time.Time
	Secret      string
	Scope       string
	RedirectUri string
	UserData    interface{}
}

func (c OauthClient) GetID() string            { return c.ClientID }
func (c OauthClient) GetSecret() string        { return c.Secret }
func (c OauthClient) GetRedirectUri() string   { return c.RedirectUri }
func (c OauthClient) GetUserData() interface{} { return c.UserData }

func (c OauthClient) SetID(id string)                   { c.ClientID = id }
func (c OauthClient) SetSecret(secret string)           { c.Secret = secret }
func (c OauthClient) SetRedirectUri(redirectUri string) { c.RedirectUri = redirectUri }
func (c OauthClient) SetUserData(userData string)       { c.UserData = userData }

// AddClient adds an OAuth2 client application to the database
func (dataStore *DataStore) AddClient(userID, clientID, secret, scope, redirect string) (interface{}, error) {
	// Fetch user
	u, err := dataStore.GetUserByExtID(userID)
	if err != nil {
		return nil, err
	}
	user := u.(*User)

	client := OauthClient{
		UserID:      user.ID,
		ClientID:    clientID,
		CreatedAt:   time.Now(),
		LastUsed:    time.Now(),
		Secret:      secret,
		Scope:       scope,
		RedirectUri: redirect,
	}

	dataStore.db = dataStore.db.Create(client)
	err = dataStore.db.Error
	if err != nil {
		return nil, err
	}
	return &client, nil
}

// GetClientByID an oauth client app by ClientID
func (dataStore *DataStore) GetClientByID(clientID string) (interface{}, error) {
	var client OauthClient
	err := dataStore.db.Where(&OauthClient{ClientID: clientID}).First(&client).Error
	if (err != nil) && (err != gorm.ErrRecordNotFound) {
		return nil, err
	} else if (err != nil) && (err == gorm.ErrRecordNotFound) {
		return nil, nil
	}

	return &client, nil
}

// GetClientsByUser fetches the OauthClients for a provided user
func (dataStore *DataStore) GetClientsByUser(userID string) ([]interface{}, error) {
	var oauthClients []OauthClient

	// Fetch user
	u, err := dataStore.GetUserByExtID(userID)
	if err != nil {
		return nil, err
	}
	user := u.(*User)

	err = dataStore.db.Model(user).Related(&oauthClients).Error

	interfaces := make([]interface{}, len(oauthClients))
	for i, t := range oauthClients {
		interfaces[i] = &t
	}

	return interfaces, err
}

// RemoveClientByID removes a client application by id
func (dataStore *DataStore) RemoveClientByID(clientID string) error {
	client := OauthClient{
		ClientID: clientID,
	}

	dataStore.db = dataStore.db.Delete(&client)

	return dataStore.db.Error
}
