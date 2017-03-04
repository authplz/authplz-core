package datastore

import (
"time"
)

import "github.com/jinzhu/gorm"

// Fido/U2F token object
type FidoToken struct {
	gorm.Model
	UserID      uint
	Name        string
	KeyHandle   string
	PublicKey   string
	Certificate string
	Counter     uint
	LastUsed    time.Time
}

// Getters and setters for external interface compliance
func (token *FidoToken) GetName() string { return token.Name }
func (token *FidoToken) GetKeyHandle() string { return token.KeyHandle }
func (token *FidoToken) GetPublicKey() string { return token.PublicKey }
func (token *FidoToken) GetCertificate() string { return token.Certificate }
func (token *FidoToken) GetCounter() uint { return token.Counter }
func (token *FidoToken) SetCounter(count uint) { token.Counter = count }
func (token *FidoToken) GetLastUsed() time.Time { return token.LastUsed }
func (token *FidoToken) SetLastUsed(used time.Time) { token.LastUsed = used }



// Datastore methods required by Fido module
func (dataStore *DataStore) AddFidoToken(userid, name, keyHandle, publicKey, certificate string, counter uint) (interface{}, error) {

	// Fetch user
	u, err := dataStore.GetUserByExtId(userid)
	if err != nil {
		return nil, err
	}
	
	user := u.(*User)

	// Create a token instance
	token := FidoToken{
		UserID: user.ID,
		Name: name,
		KeyHandle: keyHandle,
		PublicKey: publicKey,
		Certificate: certificate,
		Counter: counter,
		LastUsed: time.Now(),
	}

	// Add the token to the user and save
	user.FidoTokens = append(user.FidoTokens, token)
	_, err = dataStore.UpdateUser(user)
	return user, err
}

func (dataStore *DataStore) GetFidoTokens(userid string) ([]interface{}, error) {
	var fidoTokens []FidoToken

	// Fetch user
	u, err := dataStore.GetUserByExtId(userid)
	if err != nil {
		return nil, err
	}
	
	user := u.(*User)

	err = dataStore.db.Model(user).Related(&fidoTokens).Error

	interfaces := make([]interface{}, len(fidoTokens))
	for i, t := range(fidoTokens) {
		interfaces[i] = &t
	}

	return interfaces, err
}

func (dataStore *DataStore) UpdateFidoToken(token interface{}) (interface{}, error) {

	err := dataStore.db.Save(token).Error
	if err != nil {
		return nil, err
	}

	return token, nil
}
