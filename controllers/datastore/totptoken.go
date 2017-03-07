package datastore

import "time"

import "github.com/jinzhu/gorm"

// TotpToken Time based One Time Password Token object
type TotpToken struct {
	gorm.Model
	UserID     uint
	Name       string
	Secret     string
	UsageCount uint
	LastUsed   time.Time
}

// Getters and setters for external interface compliance

func (token *TotpToken) GetName() string            { return token.Name }
func (token *TotpToken) GetSecret() string          { return token.Secret }
func (token *TotpToken) GetCounter() uint           { return token.UsageCount }
func (token *TotpToken) SetCounter(count uint)      { token.UsageCount = count }
func (token *TotpToken) GetLastUsed() time.Time     { return token.LastUsed }
func (token *TotpToken) SetLastUsed(used time.Time) { token.LastUsed = used }

// AddTotpToken adds a TOTP token to the provided user
func (ds *DataStore) AddTotpToken(userid, name, secret string, counter uint) (interface{}, error) {
	// Fetch user
	u, err := ds.GetUserByExtId(userid)
	if err != nil {
		return nil, err
	}

	user := u.(*User)
	totpToken := TotpToken{
		UserID:     user.ID,
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
	u, err := ds.GetUserByExtId(userid)
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
