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

func (oa *OauthAuthorizeCode) GetSession() interface{} { return &oa.OauthSession }

func (oa *OauthAuthorizeCode) SetSession(session interface{}) {
	// I don't even know what to do here
}

// AddAuthorizeCodeSession creates an authorization code session in the database
func (oauthStore *OauthStore) AddAuthorizeCodeSession(userID, clientID, code, requestID string,
	requestedAt, expiresAt time.Time, requestedScopes, grantedScopes []string) (interface{}, error) {

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

	or.SetRequestedScopes(requestedScopes)
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

	authorize.Client = *client

	return &authorize, nil
}

func (oauthStore *OauthStore) fetchAuthorizeCodeSession(match *OauthAuthorizeCode) (interface{}, error) {
	var authorize OauthAuthorizeCode
	err := oauthStore.db.Where(match).First(&authorize).Error
	if (err != nil) && (err != gorm.ErrRecordNotFound) {
		return nil, err
	} else if (err != nil) && (err == gorm.ErrRecordNotFound) {
		return nil, nil
	}

	err = oauthStore.db.Where(&OauthClient{ID: authorize.ClientID}).First(&authorize.Client).Error
	if err != nil {
		return nil, err
	}

	return &authorize, nil
}

// GetAuthorizeCodeSession fetches an authorization code session
func (oauthStore *OauthStore) GetAuthorizeCodeSession(code string) (interface{}, error) {
	return oauthStore.fetchAuthorizeCodeSession(&OauthAuthorizeCode{Code: code})
}

// GetAuthorizeCodeSessionByRequestID fetches an authorization code session by the originator request ID
func (oauthStore *OauthStore) GetAuthorizeCodeSessionByRequestID(requestID string) (interface{}, error) {
	return oauthStore.fetchAuthorizeCodeSession(&OauthAuthorizeCode{OauthRequest: OauthRequest{RequestID: requestID}})
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
