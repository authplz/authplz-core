package datastore

import (
	"time"

	"github.com/jinzhu/gorm"
	"github.com/satori/go.uuid"
)

// TotpToken Time based One Time Password Token object
type TotpToken struct {
	gorm.Model
	ExtID      string
	UserID     uint
	Name       string
	Secret     string
	UsageCount uint
	LastUsed   time.Time
}

// Getters and setters for external interface compliance

// GetName fetches the fido token Name
func (token *TotpToken) GetName() string { return token.Name }

// GetExtID fetches the external ID for a token
func (token *TotpToken) GetExtID() string { return token.ExtID }

// GetSecret fetches the fido token Secret
func (token *TotpToken) GetSecret() string { return token.Secret }

// GetCounter fetches the fido token Counter
func (token *TotpToken) GetCounter() uint { return token.UsageCount }

// SetCounter sets the fido token usage counter
func (token *TotpToken) SetCounter(count uint) { token.UsageCount = count }

// GetLastUsed fetches the fido token LastUsed time
func (token *TotpToken) GetLastUsed() time.Time { return token.LastUsed }

// SetLastUsed sets the fido token LastUsed time
func (token *TotpToken) SetLastUsed(used time.Time) { token.LastUsed = used }

// AddTotpToken adds a TOTP token to the provided user
func (ds *DataStore) AddTotpToken(userid, name, secret string, counter uint) (interface{}, error) {
	// Fetch user
	u, err := ds.GetUserByExtID(userid)
	if err != nil {
		return nil, err
	}

	user := u.(*User)
	totpToken := TotpToken{
		UserID:     user.ID,
		ExtID:      uuid.NewV4().String(),
		Name:       name,
		Secret:     secret,
		UsageCount: counter,
		LastUsed:   time.Now(),
	}

	user.TotpTokens = append(user.TotpTokens, totpToken)
	_, err = ds.UpdateUser(user)
	return &totpToken, err
}

// GetTotpTokens fetches tokens attached to a given user
func (ds *DataStore) GetTotpTokens(userid string) ([]interface{}, error) {
	var totpTokens []TotpToken

	// Fetch user
	u, err := ds.GetUserByExtID(userid)
	if err != nil {
		return nil, err
	}
	user := u.(*User)

	// Grab tokens
	err = ds.db.Model(user).Related(&totpTokens).Error

	interfaces := make([]interface{}, len(totpTokens))
	for i, t := range totpTokens {
		interfaces[i] = &t
	}

	return interfaces, err
}

// UpdateTotpToken updates a TOTP token instance in the database
func (ds *DataStore) UpdateTotpToken(token interface{}) (interface{}, error) {
	err := ds.db.Save(token).Error
	if err != nil {
		return nil, err
	}

	return token, nil
}

// DeleteTotpToken deletes a totp token
func (ds *DataStore) DeleteTotpToken(token interface{}) error {
	return ds.db.Delete(token).Error
}
