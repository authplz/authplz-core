package oauthstore

import (
	"fmt"
	"github.com/jinzhu/gorm"
	"time"
)

// OauthClient is a client application registration
type OauthClient struct {
	ID        uint      `gorm:"primary_key" description:"Internal Database ID"`
	CreatedAt time.Time `description:"Creation time"`
	UpdatedAt time.Time `description:"Last update time"`
	ClientID  string    `gorm:"unique"`
	Name      string    `gorm:"unique"`
	UserID    uint
	LastUsed  time.Time
	Secret    string

	Scopes        string
	RedirectURIs  string
	GrantTypes    string
	ResponseTypes string

	UserData string
	Public   bool
}

func (c *OauthClient) GetID() string     { return c.ClientID }
func (c *OauthClient) GetName() string   { return c.Name }
func (c *OauthClient) GetSecret() string { return c.Secret }

func (c *OauthClient) GetUserData() interface{} { return c.UserData }
func (c *OauthClient) GetLastUsed() time.Time   { return c.LastUsed }
func (c *OauthClient) GetCreatedAt() time.Time  { return c.CreatedAt }
func (c *OauthClient) IsPublic() bool           { return c.Public }

func (c *OauthClient) SetID(id string)         { c.ClientID = id }
func (c *OauthClient) SetLastUsed(t time.Time) { c.LastUsed = t }

func (c *OauthClient) SetSecret(secret string)     { c.Secret = secret }
func (c *OauthClient) SetUserData(userData string) { c.UserData = userData }

func (c *OauthClient) GetRedirectURIs() []string {
	return stringToArray(c.RedirectURIs)
}
func (c *OauthClient) GetGrantTypes() []string {
	return stringToArray(c.GrantTypes)
}
func (c *OauthClient) GetResponseTypes() []string {
	return stringToArray(c.ResponseTypes)
}
func (c *OauthClient) GetScopes() []string {
	return stringToArray(c.Scopes)
}

func (c *OauthClient) SetRedirectURIs(redirectURIs []string) {
	c.RedirectURIs = arrayToString(redirectURIs)
}
func (c *OauthClient) SetGrantTypes(grantTypes []string) {
	c.GrantTypes = arrayToString(grantTypes)
}
func (c *OauthClient) SetResponseTypes(responseTypes []string) {
	c.ResponseTypes = arrayToString(responseTypes)
}
func (c *OauthClient) SetScopes(scopes []string) {
	c.Scopes = arrayToString(scopes)
}

// AddClient adds an OAuth2 client application to the database
func (oauthStore *OauthStore) AddClient(userID, clientID, clientName, secret string,
	scopes, redirects, grantTypes, responseTypes []string, public bool) (interface{}, error) {
	// Fetch user
	u, err := oauthStore.base.GetUserByExtID(userID)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, fmt.Errorf("No user account found for userID: %s", userID)
	}
	user := u.(User)

	// Create Client object
	client := OauthClient{
		UserID:    user.GetIntID(),
		ClientID:  clientID,
		Name:      clientName,
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
		Secret:    secret,
	}
	client.SetScopes(scopes)
	client.SetRedirectURIs(redirects)
	client.SetGrantTypes(grantTypes)
	client.SetResponseTypes(responseTypes)

	// Save to store
	oauthStore.db = oauthStore.db.Create(&client)
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

// GetClientsByUserID fetches the OauthClients for a provided userID
func (oauthStore *OauthStore) GetClientsByUserID(userID string) ([]interface{}, error) {
	var oauthClients []OauthClient

	// Fetch user
	u, err := oauthStore.base.GetUserByExtID(userID)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, fmt.Errorf("No user account found for userID: %s", userID)
	}
	//user := u.(*User)

	err = oauthStore.db.Model(u).Related(&oauthClients).Error

	interfaces := make([]interface{}, len(oauthClients))
	for i, t := range oauthClients {
		interfaces[i] = &t
	}

	return interfaces, err
}

// UpdateClient Update a user object
func (oauthStore *OauthStore) UpdateClient(client interface{}) (interface{}, error) {
	c := client.(*OauthClient)

	err := oauthStore.db.Save(&c).Error
	if err != nil {
		return nil, err
	}

	return client, nil
}

// RemoveClientByID removes a client application by id
func (oauthStore *OauthStore) RemoveClientByID(clientID string) error {
	client := OauthClient{
		ClientID: clientID,
	}

	oauthStore.db = oauthStore.db.Delete(&client)

	return oauthStore.db.Error
}
