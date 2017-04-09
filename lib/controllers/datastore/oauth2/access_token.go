package oauthstore

import (
	"github.com/jinzhu/gorm"
	"time"
)

// OauthAccessToken Oauth Access token session
type OauthAccessToken struct {
	gorm.Model
	UserID    uint
	ClientID  uint
	Signature string
	OauthRequest
	OauthSession
}

func (oa *OauthAccessToken) GetSignature() string { return oa.Signature }

func (oa *OauthAccessToken) GetSession() interface{} { return &oa.OauthSession }

func (oa *OauthAccessToken) SetSession(session interface{}) {
	// I don't even know what to do here
}

func (os *OauthStore) AddAccessTokenSession(userID, clientID, signature, requestID string,
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
		RequestedAt: requestedAt,
		ExpiresAt:   expiresAt,
	}
	request.SetRequestedScopes(requestedScopes)
	request.SetGrantedScopes(grantedScopes)

	session := OauthSession{
		UserExtID:    user.GetExtID(),
		Username:     user.GetUsername(),
		AccessExpiry: expiresAt,
	}

	oa := OauthAccessToken{
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

func (os *OauthStore) fetchAccessTokenSession(match *OauthAccessToken) (interface{}, error) {
	var accessToken OauthAccessToken
	err := os.db.Where(match).First(&accessToken).Error
	if (err != nil) && (err != gorm.ErrRecordNotFound) {
		return nil, err
	} else if (err != nil) && (err == gorm.ErrRecordNotFound) {
		return nil, nil
	}

	err = os.db.Where(&OauthClient{ID: accessToken.ClientID}).First(&accessToken.Client).Error
	if err != nil {
		return nil, err
	}

	return &accessToken, nil
}

// GetAccessTokenSession Fetch a client from an access token
func (os *OauthStore) GetAccessTokenSession(signature string) (interface{}, error) {
	return os.fetchAccessTokenSession(&OauthAccessToken{Signature: signature})
}

// GetAccessTokenSessionByRequestID fetch an access token by refresh id
func (os *OauthStore) GetAccessTokenSessionByRequestID(requestID string) (interface{}, error) {
	return os.fetchAccessTokenSession(&OauthAccessToken{OauthRequest: OauthRequest{RequestID: requestID}})
}

// GetAccessTokenSessionsByUserID by a user id
func (os *OauthStore) GetAccessTokenSessionsByUserID(userID string) ([]interface{}, error) {
	var oa []OauthAccessToken
	err := os.db.Where(&OauthAccessToken{OauthSession: OauthSession{UserExtID: userID}}).Find(&oa).Error
	if err != nil {
		return nil, err
	}

	interfaces := make([]interface{}, len(oa))
	for i := range oa {
		interfaces[i] = &oa[i]
	}

	return interfaces, err
}

// GetClientByAccessTokenSession Fetch a client from an access token
func (os *OauthStore) GetClientByAccessTokenSession(signature string) (interface{}, error) {
	var oa OauthAccessToken
	err := os.db.Where(&OauthAccessToken{Signature: signature}).First(&oa).Error
	if err != nil {
		return nil, err
	}

	var oc OauthClient
	err = os.db.Where(&OauthClient{ID: oa.ClientID}).First(&oc).Error
	if err != nil {
		return nil, err
	}

	return &oc, nil
}

// RemoveAccessTokenSession Remove an access token by session key
func (os *OauthStore) RemoveAccessTokenSession(signature string) error {
	err := os.db.Delete(&OauthAccessToken{Signature: signature}).Error
	return err
}
