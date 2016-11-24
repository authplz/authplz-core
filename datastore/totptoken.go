package datastore

import "time"

import "github.com/jinzhu/gorm"


// Time based One Time Password Token object
type TotpToken struct {
	gorm.Model
	UserID     uint
	Name       string
	Secret     string
	UsageCount uint
	LastUsed   time.Time
}


func (ds *DataStore) AddTotpToken(u *User, totpToken *TotpToken) (user *User, err error) {
	u.TotpTokens = append(u.TotpTokens, *totpToken)
	u, err = ds.UpdateUser(u)
	return u, err
}


func (dataStore *DataStore) GetTotpTokens(u *User) ([]TotpToken, error) {
	var totpTokens []TotpToken

	err := dataStore.db.Model(u).Related(&totpTokens).Error

	return totpTokens, err
}

