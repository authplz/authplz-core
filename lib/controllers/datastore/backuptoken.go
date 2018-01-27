package datastore

import (
	"fmt"
	"time"
)

import "github.com/jinzhu/gorm"

// BackupToken 2fa backup code object
type BackupToken struct {
	gorm.Model
	UserID uint
	Name   string
	Secret string
	Used   bool
	UsedAt time.Time
}

// Getters and setters for external interface compliance

// GetName fetches the token Name
func (token *BackupToken) GetName() string { return token.Name }

// GetHashedSecret fetches the hashed token secret
func (token *BackupToken) GetHashedSecret() string { return token.Secret }

// IsUsed checks if a token has been used
func (token *BackupToken) IsUsed() bool { return token.Used }

// SetUsed marks a token as used
func (token *BackupToken) SetUsed() { token.Used = true }

func (token *BackupToken) GetUsedAt() time.Time { return token.UsedAt }

func (token *BackupToken) GetCreatedAt() time.Time { return token.CreatedAt }

// AddBackupToken creates a backupt token token instance to a user in the database
func (dataStore *DataStore) AddBackupToken(userid, name, secret string) (interface{}, error) {

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
		Secret: secret,
		Used:   false,
	}

	// Add the token to the user and save
	user.BackupTokens = append(user.BackupTokens, token)
	_, err = dataStore.UpdateUser(user)
	return user, err
}

// AddBackupToken creates a backupt token token instance to a user in the database
func (dataStore *DataStore) AddBackupTokens(userid string, names, secrets []string) (interface{}, error) {

	// Fetch user
	u, err := dataStore.GetUserByExtID(userid)
	if err != nil {
		return nil, err
	}

	user := u.(*User)

	if len(names) != len(secrets) {
		return nil, fmt.Errorf("Error: name and secret arrays must have matching lengths")
	}

	for i := range names {
		// Create a token instance
		token := BackupToken{
			UserID: user.ID,
			Name:   names[i],
			Secret: secrets[i],
			Used:   false,
		}
		// Add the token to the user and save
		user.BackupTokens = append(user.BackupTokens, token)
	}

	// Update user instance
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
	err = dataStore.db.Find(&BackupToken{UserID: user.ID, Name: name}).First(&backupToken).Error

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

// ClearPendingBackupTokens removes any unused backup tokens
func (dataStore *DataStore) ClearPendingBackupTokens(userid string) error {
	u, err := dataStore.GetUserByExtID(userid)
	if err != nil {
		return err
	}
	user := u.(*User)

	err = dataStore.db.Delete(&BackupToken{UserID: user.ID, Used: false}).Error
	return err
}
