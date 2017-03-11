package oauth

import (
	"github.com/RangelReale/osin"
)

// OauthAdaptor adapts a generic interface for osin compliance
type OauthAdaptor struct {
	Storer
}

// NewAdaptor creates a new wraper/adaptor around a Storer interface
func NewAdaptor(s Storer) *OauthAdaptor {
	return &OauthAdaptor{s}
}

// Clone the adaptor instance
func (oa *OauthAdaptor) Clone() osin.Storage {
	return oa
}

// Close the adaptor instance (why..?)
func (oa *OauthAdaptor) Close() {

}

// GetClient Get an OAuth client by ClientID
func (oa *OauthAdaptor) GetClient(id string) (osin.Client, error) {
	c, err := oa.GetClientByID(id)
	if err != nil {
		return nil, err
	}
	return c.(osin.Client), nil
}

// SaveAuthorize saves authorize data.
func (oa *OauthAdaptor) SaveAuthorize(ad *osin.AuthorizeData) error {
	_, err := oa.AddAuthorization(ad.Client.GetId(), ad.Code, ad.ExpiresIn, ad.Scope, ad.RedirectUri, ad.State)
	return err
}

// LoadAuthorize looks up AuthorizeData by a code.
// Client information MUST be loaded together.
// Optionally can return error if expired.
func (oa *OauthAdaptor) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	a, err := oa.GetAuthorizationByCode(code)
	if err != nil {
		return nil, err
	}

	authorization := a.(Authorizaton)

	c, err := oa.GetClientByID(authorization.GetClientID())
	if err != nil {
		return nil, err
	}

	client := c.(Client)

	//expiry := time.Until(authorization.GetExpiresIn())

	osinAuthorization := osin.AuthorizeData{
		Client:      client,
		Code:        authorization.GetCode(),
		ExpiresIn:   authorization.GetExpiresIn(),
		Scope:       authorization.GetScope(),
		RedirectUri: authorization.GetRedirectUri(),
		State:       authorization.GetState(),
		CreatedAt:   authorization.GetCreatedAt(),
	}

	return &osinAuthorization, nil
}

// RemoveAuthorize revokes or deletes the authorization code.
func (oa *OauthAdaptor) RemoveAuthorize(code string) error {
	return oa.Storer.RemoveAuthorizationByCode(code)
}

// SaveAccess writes AccessData.
// If RefreshToken is not blank, it must save in a way that can be loaded using LoadRefresh.
func (oa *OauthAdaptor) SaveAccess(*osin.AccessData) error {

	a, err := oa.GetAuthorizationByCode(code)
	if err != nil {
		return nil, err
	}
	authorization := a.(Authorizaton)

	c, err := oa.GetClientByID(authorization.GetClientID())
	if err != nil {
		return nil, err
	}
	client := c.(Client)

}

// LoadAccess retrieves access data by token. Client information MUST be loaded together.
// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
// Optionally can return error if expired.
func (oa *OauthAdaptor) LoadAccess(token string) (*osin.AccessData, error) {

}

// RemoveAccess revokes or deletes an AccessData.
func (oa *OauthAdaptor) RemoveAccess(token string) error {

}

// LoadRefresh retrieves refresh AccessData. Client information MUST be loaded together.
// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
// Optionally can return error if expired.
func (oa *OauthAdaptor) LoadRefresh(token string) (*osin.AccessData, error) {

}

// RemoveRefresh revokes or deletes refresh AccessData.
func (oa *OauthAdaptor) RemoveRefresh(token string) error {

}
