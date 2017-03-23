package oauth

import (
	"time"
)

import (
//"github.com/jinzhu/gorm"
)

// Oauth client application
type OauthAccess struct {
	ID        uint `gorm:"primary_key" description:"Internal Database ID"`
	ClientID  uint
	Signature string
	OauthRequest
}

func (os *OauthStore) AddAccessTokenSession(clientID, signature, requestID string,
	requestedAt time.Time, scopes, grantedScopes, form string) (interface{}, error) {

	client, err := os.GetClientByID(clientID)
	if err != nil {
		return nil, err
	}
	c := client.(OauthClient)

	or := OauthRequest{
		RequestID:     requestID,
		RequestedAt:   requestedAt,
		Scopes:        scopes,
		GrantedScopes: grantedScopes,
		Form:          form,
	}
	oa := OauthAccess{
		ClientID:     c.ID,
		Signature:    signature,
		OauthRequest: or,
	}

	os.db = os.db.Create(oa)
	err = os.db.Error
	if err != nil {
		return nil, err
	}
	return &oa, nil
}

// Fetch a client from an access token
func (os *OauthStore) GetAccessByToken(signature string) (interface{}, error) {
	var oa OauthAccess
	err := os.db.Where(&OauthAccess{Signature: signature}).First(&oa).Error
	if err != nil {
		return nil, err
	}

	return &oa, err
}

// Fetch a client from an access token
func (os *OauthStore) GetClientByAccessToken(signature string) (interface{}, error) {
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

	return &oc, nil

	return &oa, err
}
