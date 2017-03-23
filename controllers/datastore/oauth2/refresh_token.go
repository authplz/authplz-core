package oauth

import (
	"time"
)

import (
	"github.com/jinzhu/gorm"
)

// OauthRefreshToken Refresh token storage
type OauthRefreshToken struct {
	gorm.Model
	UserID    uint
	ClientID  uint
	Signature string
	OauthRequest
	OauthSession
}

// GetSignature fetches the Refresh token signature
func (or *OauthRefreshToken) GetSignature() string { return or.Signature }

// AddRefreshTokenSession creates a refresh token session in the database
func (os *OauthStore) AddRefreshTokenSession(userID, clientID, signature, requestID string,
	requestedAt, expiresAt time.Time, scopes, grantedScopes []string) (interface{}, error) {

	u, err := os.base.GetUserByExtID(userID)
	if err != nil {
		return nil, err
	}
	user := u.(User)

	client, err := os.GetClientByID(clientID)
	if err != nil {
		return nil, err
	}
	c := client.(*OauthClient)

	request := OauthRequest{
		RequestID:   requestID,
		RequestedAt: time.Now(),
	}
	request.SetScopes(scopes)
	request.SetGrantedScopes(grantedScopes)

	session := NewSession(user.GetExtID(), user.GetUsername())
	session.RefreshExpiry = expiresAt

	oa := OauthRefreshToken{
		ClientID:     c.ID,
		UserID:       user.GetIntID(),
		Signature:    signature,
		OauthRequest: request,
		OauthSession: session,
	}

	os.db = os.db.Create(&oa)
	err = os.db.Error
	if err != nil {
		return nil, err
	}
	return &oa, nil
}

// Fetch a client from an access token
func (os *OauthStore) GetRefreshTokenBySignature(signature string) (interface{}, error) {
	var refresh OauthRefreshToken
	err := os.db.Where(&OauthRefreshToken{Signature: signature}).First(&refresh).Error
	if err != nil {
		return nil, err
	}

	return &refresh, err
}

func (oauthStore *OauthStore) GetRefreshTokenSessionByRequestID(requestID string) (interface{}, error) {
	var refresh OauthRefreshToken
	err := oauthStore.db.Where(&OauthRefreshToken{OauthRequest: OauthRequest{RequestID: requestID}}).First(&refresh).Error
	if err != nil {
		return nil, err
	}

	return &refresh, err
}

// Fetch a client from an access token
func (os *OauthStore) GetClientByRefreshToken(signature string) (interface{}, error) {
	var refresh OauthRefreshToken
	err := os.db.Where(&OauthRefreshToken{Signature: signature}).First(&refresh).Error
	if err != nil {
		return nil, err
	}

	var client OauthClient
	err = os.db.Where(&OauthClient{ID: refresh.ClientID}).First(&client).Error
	if err != nil {
		return nil, err
	}

	return &client, nil
}

func (os *OauthStore) RemoveRefreshToken(signature string) error {
	err := os.db.Delete(&OauthRefreshToken{Signature: signature}).Error
	return err
}
