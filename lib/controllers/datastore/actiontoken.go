package datastore

import "time"

import "github.com/jinzhu/gorm"
import "fmt"

// ActionToken Time based One Time Password Token object
type ActionToken struct {
	gorm.Model
	TokenID   string
	UserExtID string
	UserID    uint
	Action    string
	Used      bool
	UsedAt    time.Time
	ExpiresAt time.Time
}

// Getters and setters for external interface compliance

// GetTokenID fetches the action token ID
func (token *ActionToken) GetTokenID() string { return token.TokenID }

func (token *ActionToken) GetUserExtID() string { return token.UserExtID }

// GetAction fetches the token action
func (token *ActionToken) GetAction() string { return token.Action }

// GetExpiry fetches the token expiry time
func (token *ActionToken) GetExpiry() time.Time { return token.ExpiresAt }

// IsUsed checks if a token has been used
func (token *ActionToken) IsUsed() bool { return token.Used }

// SetUsed sets the used state for the action token
func (token *ActionToken) SetUsed(t time.Time) {
	token.Used = true
	token.UsedAt = t
}

// CreateActionToken adds an action token to the provided user account
func (ds *DataStore) CreateActionToken(userExtID, tokenID, action string, expiry time.Time) (interface{}, error) {
	// Fetch user
	u, err := ds.GetUserByExtID(userExtID)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, fmt.Errorf("No user found by ID: %s", userExtID)
	}

	user := u.(*User)
	ActionToken := ActionToken{
		UserID:    user.ID,
		UserExtID: userExtID,
		TokenID:   tokenID,
		Action:    action,
		Used:      false,
		ExpiresAt: expiry,
	}

	user.ActionTokens = append(user.ActionTokens, ActionToken)
	_, err = ds.UpdateUser(user)
	return &ActionToken, err
}

// GetActionToken fetches an action token by token id
func (ds *DataStore) GetActionToken(tokenID string) (interface{}, error) {
	var actionToken ActionToken

	// Grab tokens
	err := ds.db.Where(&ActionToken{TokenID: tokenID}).First(&actionToken).Error

	return &actionToken, err
}

// GetActionTokens fetches tokens attached to a given user
func (ds *DataStore) GetActionTokens(userid string) ([]interface{}, error) {
	var ActionTokens []ActionToken

	// Fetch user
	u, err := ds.GetUserByExtID(userid)
	if err != nil {
		return nil, err
	}

	user := u.(*User)

	// Grab tokens
	err = ds.db.Model(user).Related(&ActionTokens).Error

	interfaces := make([]interface{}, len(ActionTokens))
	for i, t := range ActionTokens {
		interfaces[i] = &t
	}

	return interfaces, err
}

// UpdateActionToken updates a TOTP token instance in the database
func (ds *DataStore) UpdateActionToken(token interface{}) (interface{}, error) {

	err := ds.db.Save(token).Error
	if err != nil {
		return nil, err
	}

	return token, nil
}
