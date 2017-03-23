package oauth

import (
	"github.com/jinzhu/gorm"
	"log"
	"time"
)

// OauthAccess Oauth Access token session
type OauthAccess struct {
	gorm.Model
	ClientID  uint
	Signature string
	OauthRequest
}

func (oa *OauthAccess) GetSignature() string { return oa.Signature }

func (os *OauthStore) AddAccessTokenSession(clientID, signature, requestID string,
	requestedAt time.Time, scopes, grantedScopes []string) (interface{}, error) {

	client, err := os.GetClientByID(clientID)
	if err != nil {
		return nil, err
	}
	c := client.(*OauthClient)

	or := OauthRequest{
		RequestID:   requestID,
		RequestedAt: requestedAt,
	}

	or.SetScopes(scopes)
	or.SetGrantedScopes(grantedScopes)

	oa := OauthAccess{
		ClientID:     c.ID,
		Signature:    signature,
		OauthRequest: or,
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
	var oa OauthAccess
	err := os.db.Where(&OauthAccess{Signature: signature}).First(&oa).Error
	if err != nil {
		return nil, err
	}

	return &oa, err
}

func (os *OauthStore) GetAccessTokenSessionByRequestID(requestID string) (interface{}, error) {
	var oa OauthAccess
	err := os.db.Where(&OauthAccess{OauthRequest: OauthRequest{RequestID: requestID}}).First(&oa).Error
	if err != nil {
		return nil, err
	}

	return &oa, err
}

// Fetch a client from an access token
func (os *OauthStore) GetClientByAccessTokenSession(signature string) (interface{}, error) {
	var oa OauthAccess
	err := os.db.Where(&OauthAccess{Signature: signature}).First(&oa).Error
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
	err := os.db.Delete(&OauthAccess{Signature: signature}).Error
	return err
}
