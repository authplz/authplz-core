package datastore

import "time"

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

func (ds *DataStore) AddFidoToken(u *User, fidoToken *FidoToken) (*User, error) {
	//u := user.(*User)
	u.FidoTokens = append(u.FidoTokens, *fidoToken)
	_, err := ds.UpdateUser(u)
	return u, err
}

func (dataStore *DataStore) GetFidoTokens(u *User) ([]FidoToken, error) {
	var fidoTokens []FidoToken

	//u := user.(*User)

	err := dataStore.db.Model(u).Related(&fidoTokens).Error

	return fidoTokens, err
}

func (dataStore *DataStore) UpdateFidoToken(token *FidoToken) (*FidoToken, error) {

	err := dataStore.db.Save(&token).Error
	if err != nil {
		return nil, err
	}

	return token, nil
}
