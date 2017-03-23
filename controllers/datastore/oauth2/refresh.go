package oauth

import (
	"time"
)

import (
	"github.com/jinzhu/gorm"
)

// OauthRefresh Refresh token storage
type OauthRefresh struct {
	gorm.Model
	ClientID        uint
	Signature       string
	Username        string
	Subject         string
	AccessExpiry    time.Time
	RefreshExpiry   time.Time
	AuthorizeExpiry time.Time
	IDExpiry        time.Time
	OauthRequest
}

//AccessExpiry, RefreshExpiry, AuthorizeExpiry, IDExpiry time.Time
func (os *OauthStore) AddRefreshTokenSession(clientID, signature, requestID string, requestedAt time.Time, scopes, grantedScopes []string) (interface{}, error) {

	client, err := os.GetClientByID(clientID)
	if err != nil {
		return nil, err
	}
	c := client.(*OauthClient)

	or := OauthRequest{
		RequestID:   requestID,
		RequestedAt: time.Now(),
	}
	oa := OauthRefresh{
		ClientID:  c.ID,
		Signature: signature,
		//AccessExpiry:    AccessExpiry,
		//RefreshExpiry:   RefreshExpiry,
		//AuthorizeExpiry: AuthorizeExpiry,
		//IDExpiry:        IDExpiry,
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
func (os *OauthStore) GetRefreshTokenBySignature(signature string) (interface{}, error) {
	var oa OauthAccess
	err := os.db.Where(&OauthRefresh{Signature: signature}).First(&oa).Error
	if err != nil {
		return nil, err
	}

	return &oa, err
}

// Fetch a client from an access token
func (os *OauthStore) GetClientByRefreshToken(signature string) (interface{}, error) {
	var oa OauthAccess
	err := os.db.Where(&OauthRefresh{Signature: signature}).First(&oa).Error
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

func (os *OauthStore) RemoveRefreshToken(signature string) error {
	err := os.db.Delete(&OauthRefresh{Signature: signature}).Error
	return err
}
