package oauth2

import (
	"time"
)

import (
	"github.com/jinzhu/gorm"
)

type OauthClient struct {
	gorm.Model
	UserID      uint
	ClientID    string
	CreatedAt   time.Time
	LastUsed    time.Time
	Secret      string
	Scope       string
	RedirectURI string
	UserData    string
}

func (c OauthClient) GetID() string            { return c.ClientID }
func (c OauthClient) GetSecret() string        { return c.Secret }
func (c OauthClient) GetRedirectURI() string   { return c.RedirectURI }
func (c OauthClient) GetUserData() interface{} { return c.UserData }

func (c OauthClient) SetID(id string)                   { c.ClientID = id }
func (c OauthClient) SetSecret(secret string)           { c.Secret = secret }
func (c OauthClient) SetRedirectURI(RedirectURI string) { c.RedirectURI = RedirectURI }
func (c OauthClient) SetUserData(userData string)       { c.UserData = userData }

// AddClient adds an OAuth2 client application to the database
func (oauthStore *OauthStore) AddClient(userID, clientID, secret, scope, redirect string) (interface{}, error) {
	// Fetch user
	u, err := oauthStore.base.GetUserByExtID(userID)
	if err != nil {
		return nil, err
	}
	user := u.(User)

	client := OauthClient{
		UserID:      user.GetIntID(),
		ClientID:    clientID,
		CreatedAt:   time.Now(),
		LastUsed:    time.Now(),
		Secret:      secret,
		Scope:       scope,
		RedirectURI: redirect,
	}

	oauthStore.db = oauthStore.db.Create(client)
	err = oauthStore.db.Error
	if err != nil {
		return nil, err
	}
	return &client, nil
}

// GetClientByID an oauth client app by ClientID
func (oauthStore *OauthStore) GetClientByID(clientID string) (interface{}, error) {
	var client OauthClient
	err := oauthStore.db.Where(&OauthClient{ClientID: clientID}).First(&client).Error
	if (err != nil) && (err != gorm.ErrRecordNotFound) {
		return nil, err
	} else if (err != nil) && (err == gorm.ErrRecordNotFound) {
		return nil, nil
	}

	return &client, nil
}

// GetClientsByUser fetches the OauthClients for a provided user
func (oauthStore *OauthStore) GetClientsByUser(userID string) ([]interface{}, error) {
	var oauthClients []OauthClient

	// Fetch user
	u, err := oauthStore.base.GetUserByExtID(userID)
	if err != nil {
		return nil, err
	}
	user := u.(*User)

	err = oauthStore.db.Model(user).Related(&oauthClients).Error

	interfaces := make([]interface{}, len(oauthClients))
	for i, t := range oauthClients {
		interfaces[i] = &t
	}

	return interfaces, err
}

// RemoveClientByID removes a client application by id
func (oauthStore *OauthStore) RemoveClientByID(clientID string) error {
	client := OauthClient{
		ClientID: clientID,
	}

	oauthStore.db = oauthStore.db.Delete(&client)

	return oauthStore.db.Error
}
