package oauthstore

import (
	"github.com/jinzhu/gorm"
	"log"
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

func (os *OauthStore) AddAccessTokenSession(userID, clientID, signature, requestID string,
	requestedAt, expiresAt time.Time, scopes, grantedScopes []string) (interface{}, error) {

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
	}
	request.SetScopes(scopes)
	request.SetGrantedScopes(grantedScopes)

	session := NewSession(user.GetExtID(), user.GetUsername())
	session.AccessExpiry = expiresAt

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
	return &oa, nil
}

// Fetch a client from an access token
func (os *OauthStore) GetAccessTokenSession(signature string) (interface{}, error) {
	var oa OauthAccessToken
	err := os.db.Where(&OauthAccessToken{Signature: signature}).First(&oa).Error
	if err != nil {
		return nil, err
	}

	return &oa, err
}

func (os *OauthStore) GetAccessTokenSessionByRequestID(requestID string) (interface{}, error) {
	var oa OauthAccessToken
	err := os.db.Where(&OauthAccessToken{OauthRequest: OauthRequest{RequestID: requestID}}).First(&oa).Error
	if err != nil {
		return nil, err
	}

	return &oa, err
}

// Fetch a client from an access token
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

	log.Printf("GetClientByAccessToken")

	return &oc, nil
}

func (os *OauthStore) RemoveAccessTokenSession(signature string) error {
	err := os.db.Delete(&OauthAccessToken{Signature: signature}).Error
	return err
}
