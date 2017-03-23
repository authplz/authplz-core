package oauth

import (
	"github.com/jinzhu/gorm"
	"time"
)

// OauthAuthorize Authorization data
type OauthAuthorize struct {
	gorm.Model
	ClientID        uint
	Code            string // Authorization code
	Challenge       string // Optional code_challenge as described in rfc7636
	ChallengeMethod string // Optional code_challenge_method as described in rfc7636
	OauthRequest
}

func (ad *OauthAuthorize) GetCode() string         { return ad.Code }
func (ad *OauthAuthorize) GetCreatedAt() time.Time { return ad.CreatedAt }

// AddAuthorizeCodeSession creates an authorization code session in the database
func (oauthStore *OauthStore) AddAuthorizeCodeSession(clientID, code, requestID string, requestedAt time.Time, scopes, grantedScopes []string) (interface{}, error) {
	c, err := oauthStore.GetClientByID(clientID)
	if err != nil {
		return nil, err
	}
	client := c.(*OauthClient)

	or := OauthRequest{
		RequestID:   requestID,
		RequestedAt: requestedAt,
	}

	or.SetScopes(scopes)
	or.SetGrantedScopes(grantedScopes)

	authorize := OauthAuthorize{
		ClientID:     client.ID,
		Code:         code,
		OauthRequest: or,
	}

	oauthStore.db = oauthStore.db.Create(authorize)
	err = oauthStore.db.Error
	if err != nil {
		return nil, err
	}
	return &client, nil
}

// GetAuthorizeCodeSession fetches an authorization code session
func (oauthStore *OauthStore) GetAuthorizeCodeSession(code string) (interface{}, error) {
	var authorize OauthAuthorize
	err := oauthStore.db.Where(&OauthAuthorize{Code: code}).First(&authorize).Error
	if (err != nil) && (err != gorm.ErrRecordNotFound) {
		return nil, err
	} else if (err != nil) && (err == gorm.ErrRecordNotFound) {
		return nil, nil
	}

	return &authorize, nil
}

// GetAuthorizeCodeSessionByRequestID fetches an authorization code session by the originator request ID
func (oauthStore *OauthStore) GetAuthorizeCodeSessionByRequestID(requestID string) (interface{}, error) {
	var oa OauthAuthorize
	err := oauthStore.db.Where(&OauthAuthorize{OauthRequest: OauthRequest{RequestID: requestID}}).First(&oa).Error
	if err != nil {
		return nil, err
	}

	return &oa, err
}

// RemoveAuthorizeCodeSession removes an authorization code session using the provided code
func (oauthStore *OauthStore) RemoveAuthorizeCodeSession(code string) error {
	authorization := OauthAuthorize{
		Code: code,
	}

	oauthStore.db = oauthStore.db.Delete(&authorization)

	return oauthStore.db.Error
}
