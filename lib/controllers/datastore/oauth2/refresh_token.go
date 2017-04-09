package oauthstore

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

func (or *OauthRefreshToken) GetSession() interface{} { return &or.OauthSession }

func (or *OauthRefreshToken) SetSession(session interface{}) {
	// I don't even know what to do here
}

// AddRefreshTokenSession creates a refresh token session in the database
func (os *OauthStore) AddRefreshTokenSession(userID, clientID, signature, requestID string,
	requestedAt, expiresAt time.Time, requestedScopes, grantedScopes []string) (interface{}, error) {

	u, err := os.base.GetUserByExtID(userID)
	if err != nil {
		return nil, err
	}
	user := u.(User)

	c, err := os.GetClientByID(clientID)
	if err != nil {
		return nil, err
	}
	client := c.(*OauthClient)

	request := OauthRequest{
		RequestID:   requestID,
		RequestedAt: time.Now(),
	}
	request.SetRequestedScopes(requestedScopes)
	request.SetGrantedScopes(grantedScopes)

	session := NewSession(user.GetExtID(), user.GetUsername())
	session.RefreshExpiry = expiresAt

	oa := OauthRefreshToken{
		ClientID:     client.ID,
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

	oa.Client = *client

	return &oa, nil
}

func (os *OauthStore) fetchRefreshTokenSession(match *OauthRefreshToken) (interface{}, error) {
	var refreshToken OauthRefreshToken
	err := os.db.Where(match).First(&refreshToken).Error
	if (err != nil) && (err != gorm.ErrRecordNotFound) {
		return nil, err
	} else if (err != nil) && (err == gorm.ErrRecordNotFound) {
		return nil, nil
	}

	err = os.db.Where(&OauthClient{ID: refreshToken.ClientID}).First(&refreshToken.Client).Error
	if err != nil {
		return nil, err
	}

	return &refreshToken, nil
}

// Fetch a client from an access token
func (os *OauthStore) GetRefreshTokenBySignature(signature string) (interface{}, error) {
	return os.fetchRefreshTokenSession(&OauthRefreshToken{Signature: signature})
}

func (os *OauthStore) GetRefreshTokenSessionByRequestID(requestID string) (interface{}, error) {
	return os.fetchRefreshTokenSession(&OauthRefreshToken{OauthRequest: OauthRequest{RequestID: requestID}})
}

func (os *OauthStore) GetRefreshTokenSessionsByUserID(userID string) ([]interface{}, error) {
	var refreshes []OauthRefreshToken
	err := os.db.Where(&OauthRefreshToken{OauthSession: OauthSession{UserExtID: userID}}).Find(&refreshes).Error
	if err != nil {
		return nil, err
	}

	interfaces := make([]interface{}, len(refreshes))
	for i := range refreshes {
		interfaces[i] = &refreshes[i]
	}

	return interfaces, err
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
