// Adaptor to map from generic interfaces to those required by fosite

package oauth

import (
	"github.com/ory-am/fosite"
	"golang.org/x/net/context"
)

// OauthAdaptor adapts a generic interface for Fosite compliance
type OauthAdaptor struct {
	Storer
}

func NewAdaptor(s Storer) *OauthAdaptor {
	return &OauthAdaptor{s}
}

// Get an OAuth client by ClientID
func (oa *OauthAdaptor) GetClient(id string) (fosite.Client, error) {
	c, err := oa.GetClientByID(id)
	if err != nil {
		return nil, err
	}
	return c.(fosite.Client), nil
}

func (oa *OauthAdaptor) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) (err error) {
	return nil
}

func (oa *OauthAdaptor) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (request fosite.Requester, err error) {
	return nil, nil
}

func (oa *OauthAdaptor) DeleteAuthorizeCodeSession(ctx context.Context, code string) (err error) {
	return nil
}

func (oa *OauthAdaptor) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) (err error) {

	return nil
}

func (oa *OauthAdaptor) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (request fosite.Requester, err error) {

	return nil, nil
}

func (oa *OauthAdaptor) DeleteAccessTokenSession(ctx context.Context, signature string) (err error) {

	return nil
}

func (oa *OauthAdaptor) CreateRefreshTokenSession(ctx context.Context, signature string, request fosite.Requester) (err error) {
	return nil
}

func (oa *OauthAdaptor) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (request fosite.Requester, err error) {
	return nil, nil
}

func (oa *OauthAdaptor) DeleteRefreshTokenSession(ctx context.Context, signature string) (err error) {
	return nil
}

func (oa *OauthAdaptor) PersistRefreshTokenGrantSession(ctx context.Context, requestRefreshSignature, accessSignature, refreshSignature string, request fosite.Requester) error {
	return nil
}
