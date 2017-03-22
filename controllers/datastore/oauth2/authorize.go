package oauth2

import (
	"time"
)

import (
	"github.com/jinzhu/gorm"
)

// OauthAuthorize Authorization data
type OauthAuthorize struct {
	gorm.Model

	ClientID uint

	ExtClientID string

	// Authorization code
	Code string

	// Token expiration in seconds
	ExpiresIn int32

	// Requested scope
	Scope string

	// Redirect Uri from request
	RedirectUri string

	// State data from request
	State string

	// Date created
	CreatedAt time.Time

	// Data to be passed to storage. Not used by the library.
	UserData string

	// Optional code_challenge as described in rfc7636
	CodeChallenge string

	// Optional code_challenge_method as described in rfc7636
	CodeChallengeMethod string
}

func (ad *OauthAuthorize) GetClientID() string     { return ad.ExtClientID }
func (ad *OauthAuthorize) GetCode() string         { return ad.Code }
func (ad *OauthAuthorize) GetExpiresIn() int32     { return ad.ExpiresIn }
func (ad *OauthAuthorize) GetScope() string        { return ad.Scope }
func (ad *OauthAuthorize) GetRedirectUri() string  { return ad.RedirectUri }
func (ad *OauthAuthorize) GetState() string        { return ad.State }
func (ad *OauthAuthorize) GetCreatedAt() time.Time { return ad.CreatedAt }

// AddAuthorization creates an authorization in the database
func (oauthStore *OauthStore) AddAuthorization(clientID, code string, expires int32, scope, redirect, state string) (interface{}, error) {
	c, err := oauthStore.GetClientByID(clientID)
	if err != nil {
		return nil, err
	}
	client := c.(*OauthClient)

	authorize := OauthAuthorize{
		ClientID:    client.ID,
		ExtClientID: clientID,
		Code:        code,
		ExpiresIn:   expires,
		Scope:       scope,
		State:       state,
		CreatedAt:   time.Now(),
		RedirectUri: redirect,
	}

	oauthStore.db = oauthStore.db.Create(authorize)
	err = oauthStore.db.Error
	if err != nil {
		return nil, err
	}
	return &client, nil
}

// GetAuthorizationByCode Fetch an authorization by authorization code
func (oauthStore *OauthStore) GetAuthorizationByCode(code string) (interface{}, error) {
	var authorize OauthAuthorize
	err := oauthStore.db.Where(&OauthAuthorize{Code: code}).First(&authorize).Error
	if (err != nil) && (err != gorm.ErrRecordNotFound) {
		return nil, err
	} else if (err != nil) && (err == gorm.ErrRecordNotFound) {
		return nil, nil
	}

	return &authorize, nil
}

// RemoveClientByID removes a client application by id
func (oauthStore *OauthStore) RemoveAuthorizationByCode(code string) error {
	authorization := OauthAuthorize{
		Code: code,
	}

	oauthStore.db = oauthStore.db.Delete(&authorization)

	return oauthStore.db.Error
}