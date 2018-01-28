package datastore

import (
	"time"

	"github.com/jinzhu/gorm"
	"github.com/satori/go.uuid"
)

// FidoToken Fido/U2F token object
type FidoToken struct {
	gorm.Model
	ExtID       string
	UserID      uint
	Name        string
	KeyHandle   string
	PublicKey   string
	Certificate string
	Counter     uint
	LastUsed    time.Time
}

// Getters and setters for external interface compliance

// GetName fetches the token Name
func (token *FidoToken) GetName() string { return token.Name }

// GetExtID fetches the external ID for a token
func (token *FidoToken) GetExtID() string { return token.ExtID }

// GetKeyHandle fetches the token KeyHandle
func (token *FidoToken) GetKeyHandle() string { return token.KeyHandle }

// GetPublicKey fetches the token PublicKey
func (token *FidoToken) GetPublicKey() string { return token.PublicKey }

// GetCertificate fetches the token Certificate
func (token *FidoToken) GetCertificate() string { return token.Certificate }

// GetCounter fetches the token usage counter
func (token *FidoToken) GetCounter() uint { return token.Counter }

// SetCounter Sets the token usage counter
func (token *FidoToken) SetCounter(count uint) { token.Counter = count }

// GetLastUsed fetches the token LastUsed time
func (token *FidoToken) GetLastUsed() time.Time { return token.LastUsed }

// SetLastUsed sets the token LastUsed time
func (token *FidoToken) SetLastUsed(used time.Time) { token.LastUsed = used }

// AddFidoToken creates a fido token instance in the database
func (dataStore *DataStore) AddFidoToken(userid, name, keyHandle, publicKey, certificate string, counter uint) (interface{}, error) {

	// Fetch user
	u, err := dataStore.GetUserByExtID(userid)
	if err != nil {
		return nil, err
	}

	user := u.(*User)

	// Create a token instance
	token := FidoToken{
		ExtID:       uuid.NewV4().String(),
		UserID:      user.ID,
		Name:        name,
		KeyHandle:   keyHandle,
		PublicKey:   publicKey,
		Certificate: certificate,
		Counter:     counter,
		LastUsed:    time.Now(),
	}

	// Add the token to the user and save
	user.FidoTokens = append(user.FidoTokens, token)
	_, err = dataStore.UpdateUser(user)
	return user, err
}

// GetFidoTokens fetches the fido tokens for a provided user
func (dataStore *DataStore) GetFidoTokens(userid string) ([]interface{}, error) {
	var fidoTokens []FidoToken

	// Fetch user
	u, err := dataStore.GetUserByExtID(userid)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, ErrUserNotFound
	}

	err = dataStore.db.Model(u).Related(&fidoTokens).Error

	interfaces := make([]interface{}, len(fidoTokens))
	for i, t := range fidoTokens {
		interfaces[i] = &t
	}

	return interfaces, err
}

// UpdateFidoToken updates a fido token instance
func (dataStore *DataStore) UpdateFidoToken(token interface{}) (interface{}, error) {
	err := dataStore.db.Save(token).Error
	if err != nil {
		return nil, err
	}
	return token, nil
}

// RemoveFidoToken deletes a totp token
func (dataStore *DataStore) RemoveFidoToken(token interface{}) error {
	return dataStore.db.Delete(token).Error
}
