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

func (or *OauthRefresh) GetSignature() string { return or.Signature }

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
	or.SetScopes(scopes)
	or.SetGrantedScopes(grantedScopes)

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
	var refresh OauthRefresh
	err := os.db.Where(&OauthRefresh{Signature: signature}).First(&refresh).Error
	if err != nil {
		return nil, err
	}

	return &refresh, err
}

func (oauthStore *OauthStore) GetRefreshTokenSessionByRequestID(requestID string) (interface{}, error) {
	var refresh OauthRefresh
	err := oauthStore.db.Where(&OauthRefresh{OauthRequest: OauthRequest{RequestID: requestID}}).First(&refresh).Error
	if err != nil {
		return nil, err
	}

	return &refresh, err
}

// Fetch a client from an access token
func (os *OauthStore) GetClientByRefreshToken(signature string) (interface{}, error) {
	var refresh OauthRefresh
	err := os.db.Where(&OauthRefresh{Signature: signature}).First(&refresh).Error
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
	err := os.db.Delete(&OauthRefresh{Signature: signature}).Error
	return err
}
