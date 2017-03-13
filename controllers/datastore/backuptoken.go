package datastore

import (
	"time"
)

import "github.com/jinzhu/gorm"

// BackupToken 2fa backup code object
type BackupToken struct {
	gorm.Model
	UserID   uint
	Name     string
	Key      string
	Used     bool
	LastUsed time.Time
}

// Getters and setters for external interface compliance

// GetName fetches the token Name
func (token *BackupToken) GetName() string { return token.Name }

// GetKeyHandle fetches the token KeyHandle
func (token *BackupToken) GetHashedKey() string { return token.Key }

// GetPublicKey fetches the token PublicKey
func (token *BackupToken) IsUsed() bool { return token.Used }

// GetCertificate fetches the token Certificate
func (token *BackupToken) SetUsed() { token.Used = true }

// AddBackupToken creates a backupt token token instance to a user in the database
func (dataStore *DataStore) AddBackupToken(userid, name, key string) (interface{}, error) {

	// Fetch user
	u, err := dataStore.GetUserByExtID(userid)
	if err != nil {
		return nil, err
	}

	user := u.(*User)

	// Create a token instance
	token := BackupToken{
		UserID: user.ID,
		Name:   name,
		Key:    key,
		Used:   false,
	}

	// Add the token to the user and save
	user.BackupTokens = append(user.BackupTokens, token)
	_, err = dataStore.UpdateUser(user)
	return user, err
}

// GetBackupTokens fetches the backup tokens for the specified user
func (dataStore *DataStore) GetBackupTokens(userid string) ([]interface{}, error) {
	var BackupTokens []BackupToken

	// Fetch user
	u, err := dataStore.GetUserByExtID(userid)
	if err != nil {
		return nil, err
	}

	user := u.(*User)

	err = dataStore.db.Model(user).Related(&BackupTokens).Error

	interfaces := make([]interface{}, len(BackupTokens))
	for i, t := range BackupTokens {
		interfaces[i] = &t
	}

	return interfaces, err
}

// GetBackupTokenByName fetches the named backup token for a specified user
func (dataStore *DataStore) GetBackupTokenByName(userid, name string) (interface{}, error) {
	var backupToken BackupToken

	// Fetch user
	u, err := dataStore.GetUserByExtID(userid)
	if err != nil {
		return nil, err
	}
	user := u.(*User)

	// Fetch backup token
	err = dataStore.db.Model(user).Find(&backupToken, &BackupToken{UserID: user.ID, Name: name}).Error

	return &backupToken, err
}

// UpdateBackupToken updates a backup token instance
func (dataStore *DataStore) UpdateBackupToken(token interface{}) (interface{}, error) {

	err := dataStore.db.Save(token).Error
	if err != nil {
		return nil, err
	}

	return token, nil
}
