package oauthstore

import (
	"github.com/jinzhu/gorm"
	"time"
)

// OauthAuthorizeCode Authorization data
type OauthAuthorizeCode struct {
	gorm.Model
	ClientID        uint
	UserID          uint
	Code            string // Authorization code
	Challenge       string // Optional code_challenge as described in rfc7636
	ChallengeMethod string // Optional code_challenge_method as described in rfc7636
	OauthRequest
	OauthSession
}

func (oa *OauthAuthorizeCode) GetCode() string { return oa.Code }

// AddAuthorizeCodeSession creates an authorization code session in the database
func (oauthStore *OauthStore) AddAuthorizeCodeSession(userID, clientID, code, requestID string,
	requestedAt, expiresAt time.Time, scopes, grantedScopes []string) (interface{}, error) {

	u, err := oauthStore.base.GetUserByExtID(userID)
	if err != nil {
		return nil, err
	}
	user := u.(User)

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

	session := NewSession(user.GetExtID(), user.GetUsername())
	session.AuthorizeExpiry = expiresAt

	authorize := OauthAuthorizeCode{
		ClientID:     client.ID,
		UserID:       user.GetIntID(),
		Code:         code,
		OauthRequest: or,
		OauthSession: session,
	}

	oauthStore.db = oauthStore.db.Create(&authorize)
	err = oauthStore.db.Error
	if err != nil {
		return nil, err
	}
	return &client, nil
}

// GetAuthorizeCodeSession fetches an authorization code session
func (oauthStore *OauthStore) GetAuthorizeCodeSession(code string) (interface{}, error) {
	var authorize OauthAuthorizeCode
	err := oauthStore.db.Where(&OauthAuthorizeCode{Code: code}).First(&authorize).Error
	if (err != nil) && (err != gorm.ErrRecordNotFound) {
		return nil, err
	} else if (err != nil) && (err == gorm.ErrRecordNotFound) {
		return nil, nil
	}

	return &authorize, nil
}

// GetAuthorizeCodeSessionByRequestID fetches an authorization code session by the originator request ID
func (oauthStore *OauthStore) GetAuthorizeCodeSessionByRequestID(requestID string) (interface{}, error) {
	var oa OauthAuthorizeCode
	err := oauthStore.db.Where(&OauthAuthorizeCode{OauthRequest: OauthRequest{RequestID: requestID}}).First(&oa).Error
	if err != nil {
		return nil, err
	}

	return &oa, err
}

func (os *OauthStore) GetAuthorizeCodeSessionsByUserID(userID string) ([]interface{}, error) {
	var codes []OauthAuthorizeCode
	err := os.db.Where(&OauthAuthorizeCode{OauthSession: OauthSession{UserExtID: userID}}).Find(&codes).Error
	if err != nil {
		return nil, err
	}

	interfaces := make([]interface{}, len(codes))
	for i := range codes {
		interfaces[i] = &codes[i]
	}

	return interfaces, err
}

// RemoveAuthorizeCodeSession removes an authorization code session using the provided code
func (oauthStore *OauthStore) RemoveAuthorizeCodeSession(code string) error {
	authorization := OauthAuthorizeCode{
		Code: code,
	}

	oauthStore.db = oauthStore.db.Delete(&authorization)

	return oauthStore.db.Error
}
